param(
  [Parameter(Mandatory = $true)][string]$RequestPath,
  [Parameter(Mandatory = $true)][string]$ResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$nativeSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace LastAperture.WindowsProcess
{
    public sealed class JobRunResult
    {
        public long? Code;
        public bool TimedOut;
        public bool OutputLimitExceeded;
        public bool LogLimitExceeded;
        public bool LogIntegrityFailed;
        public long LogBytes;
        public bool SpawnError;
        public bool TerminationConfirmed;
        public long DurationMs;
    }

    internal sealed class CaptureBudget
    {
        private readonly object gate = new object();
        private readonly IntPtr job;
        private long remaining;
        private bool exceeded;
        private bool failed;

        internal CaptureBudget(IntPtr jobHandle, long maximumBytes)
        {
            job = jobHandle;
            remaining = maximumBytes;
        }

        internal bool Exceeded
        {
            get { lock (gate) { return exceeded; } }
        }

        internal bool Failed
        {
            get { lock (gate) { return failed; } }
        }

        internal void Drain(IntPtr readHandle, string outputPath)
        {
            try
            {
                using (SafeFileHandle safeHandle = new SafeFileHandle(readHandle, true))
                using (FileStream input = new FileStream(safeHandle, FileAccess.Read, 16384, false))
                using (FileStream output = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 16384, FileOptions.SequentialScan))
                {
                    byte[] buffer = new byte[16384];
                    while (true)
                    {
                        int count = input.Read(buffer, 0, buffer.Length);
                        if (count == 0) break;
                        lock (gate)
                        {
                            int accepted = (int)Math.Min((long)count, remaining);
                            if (accepted > 0)
                            {
                                output.Write(buffer, 0, accepted);
                                remaining -= accepted;
                            }
                            if (accepted != count && !exceeded)
                            {
                                exceeded = true;
                                Native.TerminateJobObject(job, Native.CONTROLLER_TERMINATION_CODE);
                            }
                        }
                    }
                    output.Flush(true);
                }
            }
            catch
            {
                lock (gate)
                {
                    failed = true;
                    Native.TerminateJobObject(job, Native.CONTROLLER_TERMINATION_CODE);
                }
            }
        }
    }

    public static class Native
    {
        internal const uint CONTROLLER_TERMINATION_CODE = 0xE0000001;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const int JobObjectBasicAccountingInformation = 1;
        private const int JobObjectExtendedLimitInformation = 9;
        private static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
        private static readonly IntPtr PROC_THREAD_ATTRIBUTE_JOB_LIST = new IntPtr(0x0002000D);
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint WAIT_FAILED = 0xFFFFFFFF;
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            internal int nLength;
            internal IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] internal bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            internal int cb;
            internal string lpReserved;
            internal string lpDesktop;
            internal string lpTitle;
            internal uint dwX;
            internal uint dwY;
            internal uint dwXSize;
            internal uint dwYSize;
            internal uint dwXCountChars;
            internal uint dwYCountChars;
            internal uint dwFillAttribute;
            internal uint dwFlags;
            internal ushort wShowWindow;
            internal ushort cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFOEX
        {
            internal STARTUPINFO StartupInfo;
            internal IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal uint dwProcessId;
            internal uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            internal long PerProcessUserTimeLimit;
            internal long PerJobUserTimeLimit;
            internal uint LimitFlags;
            internal UIntPtr MinimumWorkingSetSize;
            internal UIntPtr MaximumWorkingSetSize;
            internal uint ActiveProcessLimit;
            internal IntPtr Affinity;
            internal uint PriorityClass;
            internal uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            internal ulong ReadOperationCount;
            internal ulong WriteOperationCount;
            internal ulong OtherOperationCount;
            internal ulong ReadTransferCount;
            internal ulong WriteTransferCount;
            internal ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            internal JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            internal IO_COUNTERS IoInfo;
            internal UIntPtr ProcessMemoryLimit;
            internal UIntPtr JobMemoryLimit;
            internal UIntPtr PeakProcessMemoryUsed;
            internal UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        {
            internal long TotalUserTime;
            internal long TotalKernelTime;
            internal long ThisPeriodTotalUserTime;
            internal long ThisPeriodTotalKernelTime;
            internal uint TotalPageFaultCount;
            internal uint TotalProcesses;
            internal uint ActiveProcesses;
            internal uint TotalTerminatedProcesses;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint length);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info, uint length, IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr list);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcess(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFOEX startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(out IntPtr readPipe, out IntPtr writePipe, ref SECURITY_ATTRIBUTES attributes, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(string name, uint access, uint share, ref SECURITY_ATTRIBUTES attributes, uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private static void Win32(bool success, string operation)
        {
            if (!success) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), operation);
        }

        private static void ValidHandle(IntPtr handle, string operation)
        {
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), operation);
        }

        private static string QuoteArgument(string value)
        {
            if (value.Length > 0 && value.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0) return value;
            StringBuilder quoted = new StringBuilder();
            quoted.Append('"');
            int slashes = 0;
            foreach (char current in value)
            {
                if (current == '\\')
                {
                    slashes++;
                }
                else if (current == '"')
                {
                    quoted.Append('\\', (slashes * 2) + 1);
                    quoted.Append('"');
                    slashes = 0;
                }
                else
                {
                    quoted.Append('\\', slashes);
                    quoted.Append(current);
                    slashes = 0;
                }
            }
            quoted.Append('\\', slashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }

        private static string CommandLine(string file, string[] arguments)
        {
            StringBuilder command = new StringBuilder(QuoteArgument(file));
            foreach (string argument in arguments)
            {
                command.Append(' ');
                command.Append(QuoteArgument(argument));
            }
            return command.ToString();
        }

        private static string BatchCommandLine(string file, string bridge)
        {
            if (bridge.IndexOf('"') >= 0 || bridge.IndexOf('\0') >= 0)
                throw new ArgumentException("invalid batch bridge path");
            return QuoteArgument(file) + " /d /q /s /c \"\"" + bridge + "\"\"";
        }

        private static IntPtr EnvironmentBlock(IDictionary<string, string> environment)
        {
            List<string> keys = new List<string>(environment.Keys);
            keys.Sort(StringComparer.OrdinalIgnoreCase);
            StringBuilder block = new StringBuilder();
            foreach (string key in keys)
            {
                if (String.IsNullOrEmpty(key) || key.IndexOf('=') >= 0 || key.IndexOf('\0') >= 0)
                    throw new ArgumentException("invalid environment name");
                string value = environment[key] ?? String.Empty;
                if (value.IndexOf('\0') >= 0) throw new ArgumentException("invalid environment value");
                block.Append(key).Append('=').Append(value).Append('\0');
            }
            block.Append('\0');
            return Marshal.StringToHGlobalUni(block.ToString());
        }

        private static bool LogsExceeded(string[] paths, long maximumBytes, out long bytes, out bool integrityFailed)
        {
            bytes = 0;
            integrityFailed = false;
            foreach (string path in paths)
            {
                try
                {
                    if (!File.Exists(path)) continue;
                    FileAttributes attributes = File.GetAttributes(path);
                    if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                    {
                        integrityFailed = true;
                        return false;
                    }
                    long length = new FileInfo(path).Length;
                    if (length > maximumBytes - bytes)
                    {
                        bytes = maximumBytes;
                        return true;
                    }
                    bytes += length;
                }
                catch
                {
                    integrityFailed = true;
                    return false;
                }
            }
            return false;
        }

        private static bool JobEmpty(IntPtr job)
        {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
            if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, out info, (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)), IntPtr.Zero))
                return false;
            return info.ActiveProcesses == 0;
        }

        public static JobRunResult Run(
            string file,
            string[] arguments,
            string batchBridge,
            string currentDirectory,
            IDictionary<string, string> environment,
            int timeoutMs,
            long maxOutputBytes,
            string stdoutPath,
            string stderrPath,
            string[] logPaths,
            long maxLogBytes)
        {
            Stopwatch clock = Stopwatch.StartNew();
            JobRunResult result = new JobRunResult();
            result.SpawnError = true;
            IntPtr job = IntPtr.Zero;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr jobList = IntPtr.Zero;
            IntPtr handleList = IntPtr.Zero;
            IntPtr environmentBlock = IntPtr.Zero;
            IntPtr stdoutRead = IntPtr.Zero;
            IntPtr stdoutWrite = IntPtr.Zero;
            IntPtr stderrRead = IntPtr.Zero;
            IntPtr stderrWrite = IntPtr.Zero;
            IntPtr stdinNull = IntPtr.Zero;
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            Task stdoutTask = null;
            Task stderrTask = null;
            CaptureBudget capture = null;
            try
            {
                job = CreateJobObject(IntPtr.Zero, null);
                ValidHandle(job, "CreateJobObject");
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                Win32(SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits, (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))), "SetInformationJobObject");

                SECURITY_ATTRIBUTES pipeAttributes = new SECURITY_ATTRIBUTES();
                pipeAttributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                pipeAttributes.bInheritHandle = true;
                Win32(CreatePipe(out stdoutRead, out stdoutWrite, ref pipeAttributes, 0), "CreatePipe stdout");
                Win32(CreatePipe(out stderrRead, out stderrWrite, ref pipeAttributes, 0), "CreatePipe stderr");
                Win32(SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0), "SetHandleInformation stdout");
                Win32(SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0), "SetHandleInformation stderr");
                stdinNull = CreateFile("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, ref pipeAttributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                ValidHandle(stdinNull, "CreateFile NUL");

                IntPtr attributeBytes = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref attributeBytes);
                attributeList = Marshal.AllocHGlobal(attributeBytes);
                Win32(InitializeProcThreadAttributeList(attributeList, 2, 0, ref attributeBytes), "InitializeProcThreadAttributeList");
                jobList = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(jobList, job);
                Win32(UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, jobList, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero), "UpdateProcThreadAttribute job");
                handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(handleList, 0, stdinNull);
                Marshal.WriteIntPtr(handleList, IntPtr.Size, stdoutWrite);
                Marshal.WriteIntPtr(handleList, IntPtr.Size * 2, stderrWrite);
                Win32(UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleList, new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero), "UpdateProcThreadAttribute handles");

                STARTUPINFOEX startup = new STARTUPINFOEX();
                startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                startup.StartupInfo.hStdInput = stdinNull;
                startup.StartupInfo.hStdOutput = stdoutWrite;
                startup.StartupInfo.hStdError = stderrWrite;
                startup.lpAttributeList = attributeList;
                environmentBlock = EnvironmentBlock(environment);
                StringBuilder commandLine = new StringBuilder(String.IsNullOrEmpty(batchBridge) ? CommandLine(file, arguments) : BatchCommandLine(file, batchBridge));
                uint flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT;
                Win32(CreateProcess(file, commandLine, IntPtr.Zero, IntPtr.Zero, true, flags, environmentBlock, currentDirectory, ref startup, out processInfo), "CreateProcess");
                result.SpawnError = false;

                CloseHandle(stdoutWrite); stdoutWrite = IntPtr.Zero;
                CloseHandle(stderrWrite); stderrWrite = IntPtr.Zero;
                CloseHandle(stdinNull); stdinNull = IntPtr.Zero;

                capture = new CaptureBudget(job, maxOutputBytes);
                IntPtr capturedStdoutRead = stdoutRead; stdoutRead = IntPtr.Zero;
                IntPtr capturedStderrRead = stderrRead; stderrRead = IntPtr.Zero;
                stdoutTask = Task.Factory.StartNew(delegate { capture.Drain(capturedStdoutRead, stdoutPath); }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
                stderrTask = Task.Factory.StartNew(delegate { capture.Drain(capturedStderrRead, stderrPath); }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

                if (ResumeThread(processInfo.hThread) == UInt32.MaxValue)
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread");
                CloseHandle(processInfo.hThread); processInfo.hThread = IntPtr.Zero;

                bool rootExited = false;
                while (true)
                {
                    uint wait = WaitForSingleObject(processInfo.hProcess, 25);
                    if (wait == WAIT_OBJECT_0) { rootExited = true; break; }
                    if (wait == WAIT_FAILED) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WaitForSingleObject");
                    if (wait != WAIT_TIMEOUT) throw new InvalidOperationException("unexpected process wait result");
                    if (capture.Exceeded) { result.OutputLimitExceeded = true; break; }
                    bool logIntegrity;
                    long logBytes;
                    if (LogsExceeded(logPaths, maxLogBytes, out logBytes, out logIntegrity))
                    {
                        result.LogLimitExceeded = true;
                        result.LogBytes = logBytes;
                        break;
                    }
                    result.LogBytes = logBytes;
                    if (logIntegrity)
                    {
                        result.LogIntegrityFailed = true;
                        break;
                    }
                    if (clock.ElapsedMilliseconds >= timeoutMs)
                    {
                        result.TimedOut = true;
                        break;
                    }
                }

                if (rootExited)
                {
                    uint exitCode;
                    Win32(GetExitCodeProcess(processInfo.hProcess, out exitCode), "GetExitCodeProcess");
                    result.Code = unchecked((int)exitCode);
                }
                TerminateJobObject(job, CONTROLLER_TERMINATION_CODE);
                WaitForSingleObject(processInfo.hProcess, 5000);

                DateTime deadline = DateTime.UtcNow.AddSeconds(5);
                while (!JobEmpty(job) && DateTime.UtcNow < deadline) Thread.Sleep(10);
                bool drainsFinished = Task.WaitAll(new Task[] { stdoutTask, stderrTask }, 5000);
                bool finalLogIntegrity;
                long finalLogBytes;
                if (LogsExceeded(logPaths, maxLogBytes, out finalLogBytes, out finalLogIntegrity))
                    result.LogLimitExceeded = true;
                result.LogBytes = finalLogBytes;
                result.LogIntegrityFailed = result.LogIntegrityFailed || finalLogIntegrity;
                result.OutputLimitExceeded = result.OutputLimitExceeded || capture.Exceeded;
                result.TerminationConfirmed = JobEmpty(job) && drainsFinished && !capture.Failed;
                return result;
            }
            finally
            {
                result.DurationMs = clock.ElapsedMilliseconds;
                if (job != IntPtr.Zero) CloseHandle(job);
                if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
                if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
                if (stdoutRead != IntPtr.Zero) CloseHandle(stdoutRead);
                if (stdoutWrite != IntPtr.Zero) CloseHandle(stdoutWrite);
                if (stderrRead != IntPtr.Zero) CloseHandle(stderrRead);
                if (stderrWrite != IntPtr.Zero) CloseHandle(stderrWrite);
                if (stdinNull != IntPtr.Zero) CloseHandle(stdinNull);
                if (attributeList != IntPtr.Zero) { DeleteProcThreadAttributeList(attributeList); Marshal.FreeHGlobal(attributeList); }
                if (jobList != IntPtr.Zero) Marshal.FreeHGlobal(jobList);
                if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
                if (environmentBlock != IntPtr.Zero) Marshal.FreeHGlobal(environmentBlock);
            }
        }
    }
}
'@

function Write-ExclusiveJson([string]$Path, [object]$Value) {
  $json = $Value | ConvertTo-Json -Compress -Depth 8
  $encoding = New-Object System.Text.UTF8Encoding($false)
  $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
  try {
    $writer = New-Object System.IO.StreamWriter($stream, $encoding)
    try { $writer.Write($json) } finally { $writer.Dispose() }
  } finally {
    if ($null -ne $stream) { $stream.Dispose() }
  }
}

$request = $null
try {
  if ((Get-Item -LiteralPath $RequestPath).Length -gt 1048576) { throw 'request too large' }
  if (Test-Path -LiteralPath $ResultPath) { throw 'result already exists' }
  $request = Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $expected = @('args', 'batch_bridge', 'cwd', 'env', 'file', 'log_paths', 'max_log_bytes', 'max_output_bytes', 'request_nonce', 'schema_version', 'stderr_path', 'stdout_path', 'timeout_ms')
  $actual = @($request.PSObject.Properties.Name | Sort-Object)
  if (($actual -join "`n") -ne (($expected | Sort-Object) -join "`n")) { throw 'request shape invalid' }
  if ($request.schema_version -ne '1.0.0') { throw 'request version invalid' }
  if ([string]$request.request_nonce -notmatch '^[a-f0-9]{64}$') { throw 'request nonce invalid' }
  if (-not [IO.Path]::IsPathRooted([string]$request.file) -or -not [IO.Path]::IsPathRooted([string]$request.cwd)) { throw 'target path invalid' }
  if (-not [IO.Path]::IsPathRooted([string]$request.stdout_path) -or -not [IO.Path]::IsPathRooted([string]$request.stderr_path)) { throw 'capture path invalid' }
  if ($null -ne $request.batch_bridge -and -not [IO.Path]::IsPathRooted([string]$request.batch_bridge)) { throw 'batch bridge path invalid' }
  $timeout = [int64]$request.timeout_ms
  $outputLimit = [int64]$request.max_output_bytes
  $logLimit = [int64]$request.max_log_bytes
  if ($timeout -lt 1 -or $timeout -gt 1800000 -or $outputLimit -lt 1 -or $outputLimit -gt 67108864 -or $logLimit -lt 1 -or $logLimit -gt 67108864) { throw 'request limits invalid' }
  $arguments = @($request.args | ForEach-Object { [string]$_ })
  if ($arguments.Count -gt 128) { throw 'argument count invalid' }
  $logs = @($request.log_paths | ForEach-Object { [string]$_ })
  if ($logs.Count -gt 8) { throw 'log path count invalid' }
  $environment = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($property in $request.env.PSObject.Properties) {
    $environment.Add([string]$property.Name, [string]$property.Value)
  }

  Add-Type -TypeDefinition $nativeSource -Language CSharp
  $batchBridge = if ($null -eq $request.batch_bridge) { $null } else { [string]$request.batch_bridge }
  $nativeResult = [LastAperture.WindowsProcess.Native]::Run(
    [string]$request.file,
    [string[]]$arguments,
    $batchBridge,
    [string]$request.cwd,
    $environment,
    [int]$timeout,
    $outputLimit,
    [string]$request.stdout_path,
    [string]$request.stderr_path,
    [string[]]$logs,
    $logLimit
  )
  Write-ExclusiveJson -Path $ResultPath -Value ([ordered]@{
    schema_version = '1.0.0'
    request_nonce = [string]$request.request_nonce
    code = $nativeResult.Code
    timed_out = $nativeResult.TimedOut
    output_limit_exceeded = $nativeResult.OutputLimitExceeded
    log_limit_exceeded = $nativeResult.LogLimitExceeded
    log_integrity_failed = $nativeResult.LogIntegrityFailed
    log_bytes = $nativeResult.LogBytes
    spawn_error = $nativeResult.SpawnError
    termination_confirmed = $nativeResult.TerminationConfirmed
    supervision = 'WINDOWS_JOB_OBJECT'
    duration_ms = $nativeResult.DurationMs
  })
  exit 0
} catch {
  if (-not (Test-Path -LiteralPath $ResultPath)) {
    Write-ExclusiveJson -Path $ResultPath -Value ([ordered]@{
      schema_version = '1.0.0'
      request_nonce = if ($null -ne $request -and $null -ne $request.request_nonce) { [string]$request.request_nonce } else { '0' * 64 }
      code = $null
      timed_out = $false
      output_limit_exceeded = $false
      log_limit_exceeded = $false
      log_integrity_failed = $false
      log_bytes = 0
      spawn_error = $true
      termination_confirmed = $false
      supervision = 'WINDOWS_JOB_OBJECT'
      duration_ms = 0
    })
  }
  exit 1
}
