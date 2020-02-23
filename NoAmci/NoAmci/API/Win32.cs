using System;
using System.Runtime.InteropServices;

namespace SPEx2 {

    public static class Win32 {

        public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, ref uint lpflOldProtect) {
           object[] funcargs =
           {
                lpAddress, dwSize, flNewProtect, lpflOldProtect
           };

            bool retVal = (bool)Generic.DynamicAPIInvoke(@"k" + "e" + "r" + "n" + "e" + "l" + "3" + "2" + "." + "d" + "l" + "l", @"Vi"+ "rt" + "ua" + "lP" + "ro" +"te" + "ct", typeof(Delegates.VirtualProtect), ref funcargs);

            lpflOldProtect = (uint)funcargs[3];

            return retVal;
        }

        private static class Delegates {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        }
    }
}