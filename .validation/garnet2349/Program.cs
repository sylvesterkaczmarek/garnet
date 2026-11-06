using System.ComponentModel;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Garnet.server.TLS;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

internal static class Program
{
    const int MissingKey = unchecked((int)0x80070002);
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    [DllImport("advapi32.dll", EntryPoint = "LogonUserW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool LogonUser(string user, string domain, string password, int logonType,
        int provider, out SafeAccessTokenHandle token);

    static string RequiredEnv(string name) => Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException("Required process environment is absent.");

    public static async Task<int> Main(string[] args)
    {
        // No exception messages/stacks: these can contain paths, account names or input data.
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("{\"status\":\"unsupported-platform\",\"exitCode\":3}");
            return 3;
        }
        try
        {
            if (args.Length == 2 && args[0] == "generate")
            {
                Generate(args[1]);
                return 0;
            }
            if (args.Length == 7 && args[0] == "run" && args[1] is "baseline" or "candidate" && args[2] is "normal" or "profileless")
                return await Run(args[1], args[2], args[3], args[4], args[5], args[6]);
            throw new ArgumentException("Invalid command.");
        }
        catch (Exception ex)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { status = "infrastructure-failure", error = Error(ex), exitCode = 3 }, Json));
            return 3;
        }
    }

    static void Generate(string directory)
    {
        Directory.CreateDirectory(directory);
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        using RSA otherKey = RSA.Create(2048);
        string pem = cert.ExportCertificatePem();
        string keyPem = key.ExportPkcs8PrivateKeyPem();
        File.WriteAllBytes(Path.Combine(directory, "encrypted.pfx"), cert.Export(X509ContentType.Pfx, RequiredEnv("GARNET2349_PFX_PASSWORD")));
        Write("cert.pem", pem);
        Write("key.pem", keyPem);
        Write("combined.pem", pem + "\n" + keyPem);
        Write("pem-renamed.pfx", pem + "\n" + keyPem);
        Write("other-key.pem", otherKey.ExportPkcs8PrivateKeyPem());
        Write("malformed.pfx", "deliberately invalid PKCS12 fixture");
        Write("fingerprint.txt", cert.GetCertHashString(HashAlgorithmName.SHA256));
        void Write(string name, string value) => File.WriteAllText(Path.Combine(directory, name), value, new UTF8Encoding(false));
    }

    sealed record TestCase(string Name, string File, string Password, string[] ReadFiles, string Negative = null);
    sealed record ErrorInfo(string Type, string HResult, int? NativeErrorCode, ErrorInfo Inner, ErrorInfo[] Causes);
    static ErrorInfo Error(Exception ex) => new(ex.GetType().FullName, $"0x{ex.HResult:X8}",
        ex is Win32Exception win32 ? win32.NativeErrorCode : null,
        ex is AggregateException || ex.InnerException is null ? null : Error(ex.InnerException),
        ex is AggregateException aggregate ? aggregate.Flatten().InnerExceptions.Select(Error).ToArray() : null);

    sealed class Snapshot
    {
        public string Phase { get; set; }
        public string EffectiveSid { get; set; }
        public string RunnerSid { get; set; }
        public string ExpectedSid { get; set; }
        public string ObservedProfileSid { get; set; }
        public bool SidMatches { get; set; }
        public bool DiffersFromRunner { get; set; }
        public bool HkuSidHivePresent { get; set; }
        public bool HkuClassesHivePresent { get; set; }
        public bool ProfileListEntryPresent { get; set; }
        public bool ProfileDirectoryPresent { get; set; }
        public bool ProfilelessVerified { get; set; }
        public bool RunnerHkuSidHivePresent { get; set; }
    }

    sealed class CaseResult
    {
        public string Name { get; set; }
        public string Identity { get; set; }
        public string Expected { get; set; }
        public string Actual { get; set; } = "not-run";
        public string Stage { get; set; } = "identity";
        public bool Passed { get; set; }
        public bool HasPrivateKey { get; set; }
        public bool FingerprintMatches { get; set; }
        public bool PrivateKeySignatureVerified { get; set; }
        public bool HandshakeCompleted { get; set; }
        public string TlsProtocol { get; set; }
        public List<Snapshot> IdentityChecks { get; } = [];
        public ErrorInfo Error { get; set; }
    }

    sealed class Summary
    {
        public int SchemaVersion { get; set; } = 1;
        public string Build { get; set; }
        public string Identity { get; set; }
        public string Case { get; set; }
        public string Os { get; set; } = RuntimeInformation.OSDescription;
        public string OsVersion { get; set; } = Environment.OSVersion.VersionString;
        public string Dotnet { get; set; } = RuntimeInformation.FrameworkDescription;
        public string Architecture { get; set; } = RuntimeInformation.ProcessArchitecture.ToString();
        public string EnvironmentLimitation { get; set; } = "Requested runner: windows-2022. Original report: Windows Server 2019. Results do not establish Server 2019 behavior.";
        public string SourceSha256 { get; set; }
        public string ProgramSha256 { get; set; }
        public string FixtureFingerprintSha256 { get; set; }
        public string RunnerSid { get; set; }
        public string TemporarySid { get; set; }
        public string Logon { get; set; } = "LogonUserW / LOGON32_LOGON_INTERACTIVE(2) / LOGON32_PROVIDER_DEFAULT(0)";
        public List<Snapshot> IdentityChecks { get; } = [];
        public List<CaseResult> Cases { get; } = [];
        public string Status { get; set; } = "infrastructure-failure";
        public ErrorInfo Error { get; set; }
        public int ExitCode { get; set; } = 3;
    }

    [SupportedOSPlatform("windows")]
    static async Task<int> Run(string build, string identity, string caseName, string source, string fixtures, string output)
    {
        var summary = new Summary { Build = build, Identity = identity, Case = caseName };
        try
        {
            summary.SourceSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(source)));
            summary.ProgramSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(source), "Program.cs"))));
            summary.FixtureFingerprintSha256 = File.ReadAllText(Path.Combine(fixtures, "fingerprint.txt")).Trim();
            using var runner = WindowsIdentity.GetCurrent();
            summary.RunnerSid = runner.User.Value;
            summary.TemporarySid = RequiredEnv("GARNET2349_SID");
            var user = RequiredEnv("GARNET2349_USER");
            var password = RequiredEnv("GARNET2349_PFX_PASSWORD");
            string P(string name) => Path.Combine(fixtures, name);
            TestCase[] cases = [
                new("encrypted-pfx", P("encrypted.pfx"), password, ["encrypted.pfx"]),
                new("separate-pem", P("cert.pem"), P("key.pem"), ["cert.pem", "key.pem"]),
                new("combined-pem", P("combined.pem"), null, ["combined.pem"]),
                new("pem-renamed-pfx", P("pem-renamed.pfx"), null, ["pem-renamed.pfx"]),
                new("missing-file", P("does-not-exist.pfx"), password, [], "missing"),
                new("wrong-password", P("encrypted.pfx"), password + "-incorrect", ["encrypted.pfx"], "crypto"),
                new("malformed-pfx", P("malformed.pfx"), password, ["malformed.pfx"], "crypto"),
                new("mismatched-pem-key", P("cert.pem"), P("other-key.pem"), ["cert.pem", "other-key.pem"], "mismatch")
            ];
            var selected = cases.Single(c => c.Name == caseName);

            Snapshot Check(string phase, bool impersonated)
            {
                using var effective = WindowsIdentity.GetCurrent();
                string effectiveSid = effective.User.Value;
                // Observe the registry/directory as the runner, so access denial cannot masquerade as absence.
                // This brief nested reversion never surrounds certificate import or TLS operations.
                return WindowsIdentity.RunImpersonated(runner.AccessToken, () =>
                    Inspect(phase, effectiveSid, runner.User.Value, summary.TemporarySid, user, impersonated));
            }
            void Require(Snapshot s, bool impersonated)
            {
                if (!s.SidMatches || (impersonated && !s.ProfilelessVerified))
                    throw new InvalidOperationException("Identity/profile invariant violated.");
            }

            var before = Check("before-logon", false);
            summary.IdentityChecks.Add(before);
            if (!before.SidMatches || before.HkuSidHivePresent || before.HkuClassesHivePresent ||
                before.ProfileListEntryPresent || before.ProfileDirectoryPresent || summary.RunnerSid == summary.TemporarySid)
                throw new InvalidOperationException("Temporary account is not fresh/profileless.");

            if (identity == "normal")
            {
                summary.Cases.Add(await Test(selected, false));
            }
            else
            {
                if (!LogonUser(user, ".", RequiredEnv("GARNET2349_PASSWORD"), 2, 0, out var token))
                {
                    int error = Marshal.GetLastWin32Error();
                    token?.Dispose();
                    throw new Win32Exception(error);
                }
                using (token)
                {
                    await WindowsIdentity.RunImpersonatedAsync(token, async () =>
                    {
                        var entered = Check("impersonation-enter", true);
                        summary.IdentityChecks.Add(entered);
                        Require(entered, true);
                        summary.Cases.Add(await Test(selected, true));
                        var leaving = Check("impersonation-exit", true);
                        summary.IdentityChecks.Add(leaving);
                        Require(leaving, true);
                    });
                }
            }
            var after = Check("after-token-disposed", false);
            summary.IdentityChecks.Add(after);
            Require(after, false);
            if (after.HkuSidHivePresent || after.HkuClassesHivePresent || after.ProfileListEntryPresent || after.ProfileDirectoryPresent)
                throw new InvalidOperationException("Profile was allocated during validation.");

            bool controlsPass = summary.Cases.Where(c => c.Identity == "normal" || c.Expected == "import-rejected").All(c => c.Passed);
            bool allPass = summary.Cases.Count == 1 && summary.Cases.All(c => c.Passed);
            bool identityPass = summary.Cases.All(c => c.Stage is "import" or "private-key" or "tls" && c.IdentityChecks.Count >= 2 &&
                c.IdentityChecks.All(s => s.SidMatches && (c.Identity == "normal" || s.ProfilelessVerified)));
            summary.ExitCode = allPass ? 0 : build == "baseline" && controlsPass && identityPass ? 2 : 1;
            summary.Status = allPass ? "expected-outcome-observed" :
                summary.ExitCode == 2 ? "inconclusive-baseline-not-reproduced" : "validation-failed";

            async Task<CaseResult> Test(TestCase test, bool impersonated)
            {
                bool expectMissingKey = build == "baseline" && impersonated && test.Negative is null;
                var result = new CaseResult
                {
                    Name = test.Name, Identity = impersonated ? "profileless" : "normal",
                    Expected = test.Negative is not null ? "import-rejected" : expectMissingKey ? "import-CryptographicException-0x80070002" : "private-key-and-loopback-tls"
                };
                try
                {
                    CheckCase("before-import");
                    result.Stage = "fixture-read";
                    foreach (string name in test.ReadFiles)
                    {
                        byte[] bytes = File.ReadAllBytes(P(name));
                        CryptographicOperations.ZeroMemory(bytes);
                    }
                    result.Stage = "import";
                    using var cert = CertificateUtils.GetMachineCertificateByFile(test.File, test.Password);
                    // Anything after the call returns (including property access or Dispose)
                    // cannot count as the expected import exception.
                    result.Stage = "post-import";
                    result.Actual = "import-returned";
                    result.HasPrivateKey = cert.HasPrivateKey;
                    result.FingerprintMatches = cert.GetCertHashString(HashAlgorithmName.SHA256) == summary.FixtureFingerprintSha256;
                    if (test.Negative is null)
                    {
                        result.Stage = "private-key";
                        if (!result.HasPrivateKey || !result.FingerprintMatches)
                            throw new InvalidOperationException("Wrong certificate or missing private key.");
                        using (RSA privateKey = cert.GetRSAPrivateKey())
                        using (RSA publicKey = cert.GetRSAPublicKey())
                        {
                            byte[] challenge = RandomNumberGenerator.GetBytes(32);
                            byte[] signature = privateKey.SignData(challenge, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                            result.PrivateKeySignatureVerified = publicKey.VerifyData(challenge, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                            if (!result.PrivateKeySignatureVerified) throw new CryptographicException("Private key verification failed.");
                        }
                        result.Stage = "tls";
                        result.TlsProtocol = await Handshake(cert, summary.FixtureFingerprintSha256, phase => CheckCase(phase));
                        result.HandshakeCompleted = true;
                        result.Actual = "private-key-and-loopback-tls";
                        result.Passed = !expectMissingKey;
                    }
                }
                catch (Exception ex)
                {
                    result.Error = Error(ex);
                    result.Actual = result.Stage + "-exception";
                    result.Passed = result.Stage == "import" && (expectMissingKey
                        ? ex is CryptographicException && ex.HResult == MissingKey
                        : test.Negative switch
                        {
                            "missing" => ex is FileNotFoundException,
                            // 0x80070002 is not evidence that a password/format/key was rejected.
                            "crypto" => ex is CryptographicException && ex.HResult != MissingKey,
                            "mismatch" => ex is CryptographicException or ArgumentException && ex.HResult != MissingKey,
                            _ => false
                        });
                }
                finally
                {
                    try { CheckCase("after-case"); }
                    catch (Exception ex) { result.Passed = false; result.Stage = "identity"; result.Error = Error(ex); result.Actual = "identity-invalid"; }
                }
                return result;

                void CheckCase(string phase)
                {
                    var snapshot = Check(phase, impersonated);
                    lock (result.IdentityChecks) result.IdentityChecks.Add(snapshot);
                    // If this check fails inside TLS, never classify it as an import reproduction.
                    Require(snapshot, impersonated);
                }
            }
        }
        catch (Exception ex) { summary.Error = Error(ex); }
        File.WriteAllText(output, JsonSerializer.Serialize(summary, Json), new UTF8Encoding(false));
        Console.WriteLine(JsonSerializer.Serialize(new { summary.Build, summary.Status, summary.ExitCode }, Json));
        return summary.ExitCode;
    }

    [SupportedOSPlatform("windows")]
    static Snapshot Inspect(string phase, string effectiveSid, string runnerSid, string temporarySid, string user, bool impersonated)
    {
        using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        using var hive = users.OpenSubKey(temporarySid);
        using var classes = users.OpenSubKey(temporarySid + "_Classes");
        using var runnerHive = users.OpenSubKey(runnerSid);
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var profiles = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
            ?? throw new InvalidOperationException("ProfileList unavailable.");
        using var entry = profiles.OpenSubKey(temporarySid);
        string root = Environment.ExpandEnvironmentVariables(profiles.GetValue("ProfilesDirectory") as string
            ?? throw new InvalidOperationException("ProfilesDirectory unavailable."));
        // Enumeration throws on inaccessible/missing root; Directory.Exists alone can hide access errors.
        bool directoryPresent = Directory.EnumerateDirectories(root).Any(path =>
            Path.GetFileName(path).Equals(user, StringComparison.OrdinalIgnoreCase) ||
            Path.GetFileName(path).StartsWith(user + ".", StringComparison.OrdinalIgnoreCase));
        return new Snapshot
        {
            Phase = phase, EffectiveSid = effectiveSid, RunnerSid = runnerSid,
            ObservedProfileSid = temporarySid, RunnerHkuSidHivePresent = runnerHive is not null,
            ExpectedSid = impersonated ? temporarySid : runnerSid,
            SidMatches = effectiveSid == (impersonated ? temporarySid : runnerSid),
            DiffersFromRunner = effectiveSid != runnerSid,
            HkuSidHivePresent = hive is not null, HkuClassesHivePresent = classes is not null,
            ProfileListEntryPresent = entry is not null, ProfileDirectoryPresent = directoryPresent,
            ProfilelessVerified = effectiveSid == temporarySid && effectiveSid != runnerSid &&
                hive is null && classes is null && entry is null && !directoryPresent
        };
    }

    static async Task<string> Handshake(X509Certificate2 cert, string expectedFingerprint, Action<string> checkIdentity)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        using var client = new TcpClient(AddressFamily.InterNetwork);
        TcpClient server = null;
        SslStream serverTls = null, clientTls = null;
        Task serverTask = null, clientTask = null;
        listener.Start(1);
        try
        {
            // Connect to a numeric loopback address; TargetHost is only used for TLS.
            await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, deadline.Token);
            server = await listener.AcceptTcpClientAsync(deadline.Token);
            serverTls = new SslStream(server.GetStream(), false);
            clientTls = new SslStream(client.GetStream(), false, (_, remote, _, _) =>
                remote is not null && Convert.ToHexString(SHA256.HashData(remote.GetRawCertData())) == expectedFingerprint);
            serverTask = Server();
            clientTask = Client();
            await Task.WhenAll(serverTask, clientTask).WaitAsync(deadline.Token);
            checkIdentity("tls-both-completed");
            return serverTls.SslProtocol.ToString();
        }
        finally
        {
            deadline.Cancel();
            serverTls?.Dispose();
            clientTls?.Dispose();
            server?.Dispose();
            client.Dispose();
            listener.Stop();
            Task both = Task.WhenAll(serverTask ?? Task.CompletedTask, clientTask ?? Task.CompletedTask);
            try { await both.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch when (both.IsCompleted) { /* Faults observed; original exception remains authoritative. */ }
            catch (TimeoutException)
            {
                // Do not report completed while TLS tasks remain alive. The runner waits for exit,
                // treats a missing summary as infrastructure failure, then performs its finally cleanup.
                Console.WriteLine("{\"status\":\"tls-cleanup-timeout\",\"exitCode\":3}");
                Environment.Exit(3);
            }
            // Preserve both endpoint errors, including nested native HRESULTs, rather than
            // reporting only the cancellation triggered by the first endpoint failure.
            if (both.IsFaulted) throw both.Exception;
        }

        async Task Server()
        {
            try
            {
                checkIdentity("tls-server-before-auth");
                await serverTls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = cert, ClientCertificateRequired = false,
                    EnabledSslProtocols = SslProtocols.Tls12, AllowTlsResume = false,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, deadline.Token);
                checkIdentity("tls-server-after-auth");
                byte[] data = new byte[1];
                await serverTls.ReadExactlyAsync(data, deadline.Token);
                if (data[0] != 0x42) throw new IOException("Unexpected loopback payload.");
                await serverTls.WriteAsync(new byte[] { 0x43 }, deadline.Token);
            }
            catch { deadline.Cancel(); throw; }
        }
        async Task Client()
        {
            try
            {
                checkIdentity("tls-client-before-auth");
                await clientTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost", EnabledSslProtocols = SslProtocols.Tls12, AllowTlsResume = false,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, deadline.Token);
                checkIdentity("tls-client-after-auth");
                await clientTls.WriteAsync(new byte[] { 0x42 }, deadline.Token);
                byte[] data = new byte[1];
                await clientTls.ReadExactlyAsync(data, deadline.Token);
                if (data[0] != 0x43) throw new IOException("Unexpected loopback payload.");
            }
            catch { deadline.Cancel(); throw; }
        }
    }
}
