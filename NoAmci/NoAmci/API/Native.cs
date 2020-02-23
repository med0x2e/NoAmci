using System;
using System.Runtime.InteropServices;
using Execute = SPEx;

namespace SPEx2 {
    public class Native {

        public static void RtlInitUnicodeString(ref Execute.Native.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString) {
            
            object[] funcargs =
            {
                DestinationString, SourceString
            };

            Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

            
            DestinationString = (Execute.Native.UNICODE_STRING)funcargs[0];
        }

        public static Execute.Native.NTSTATUS LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref Execute.Native.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle) {
            
            object[] funcargs =
            {
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            };

            Execute.Native.NTSTATUS retValue = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.LdrLoadDll), ref funcargs);

            
            ModuleHandle = (IntPtr)funcargs[3];

            return retValue;
        }

        public static Execute.Native.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess) {
            Execute.Native.NTSTATUS retValue = NtQueryInformationProcess(hProcess, Execute.Native.PROCESSINFOCLASS.ProcessBasicInformation, out IntPtr pProcInfo);
            if (retValue != Execute.Native.NTSTATUS.Success) {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            return (Execute.Native.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(Execute.Native.PROCESS_BASIC_INFORMATION));
        }

        public static void RtlZeroMemory(IntPtr Destination, int Length) {
            
            object[] funcargs =
            {
                Destination, Length
            };

            Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlZeroMemory", typeof(DELEGATES.RtlZeroMemory), ref funcargs);
        }

        public static Execute.Native.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, Execute.Native.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo) {
            int processInformationLength;
            UInt32 RetLen = 0;

            switch (processInfoClass) {
                case Execute.Native.PROCESSINFOCLASS.ProcessWow64Information:
                    pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                    RtlZeroMemory(pProcInfo, IntPtr.Size);
                    processInformationLength = IntPtr.Size;
                    break;
                case Execute.Native.PROCESSINFOCLASS.ProcessBasicInformation:
                    Execute.Native.PROCESS_BASIC_INFORMATION PBI = new Execute.Native.PROCESS_BASIC_INFORMATION();
                    pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(PBI));
                    RtlZeroMemory(pProcInfo, Marshal.SizeOf(PBI));
                    Marshal.StructureToPtr(PBI, pProcInfo, true);
                    processInformationLength = Marshal.SizeOf(PBI);
                    break;
                default:
                    throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
            }

            object[] funcargs =
            {
                hProcess, processInfoClass, pProcInfo, processInformationLength, RetLen
            };

            Execute.Native.NTSTATUS retValue = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueryInformationProcess", typeof(DELEGATES.NtQueryInformationProcess), ref funcargs);
            if (retValue != Execute.Native.NTSTATUS.Success) {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            
            pProcInfo = (IntPtr)funcargs[2];

            return retValue;
        }


        public struct DELEGATES {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlInitUnicodeString(
               ref Execute.Native.UNICODE_STRING DestinationString,
               [MarshalAs(UnmanagedType.LPWStr)]
                string SourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 LdrLoadDll(
            IntPtr PathToFile,
            UInt32 dwFlags,
            ref Execute.Native.UNICODE_STRING ModuleFileName,
            ref IntPtr ModuleHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtQueryInformationProcess(
            IntPtr processHandle,
            Execute.Native.PROCESSINFOCLASS processInformationClass,
            IntPtr processInformation,
            int processInformationLength,
            ref UInt32 returnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlZeroMemory(
        IntPtr Destination,
        int length);

        }
    }
}