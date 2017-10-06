/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System.Runtime.InteropServices;

namespace System.Security
{
    public static class Extensions
    {
        /// <summary>
        /// Compares two secure strings for equality
        /// </summary>
        /// <param name="ss1">First secure string</param>
        /// <param name="ss2">Second secure string</param>
        /// <returns><c>true</c> when <paramref name="ss1"/> equals <paramref name="ss2"/>; <c>false</c> otherwise</returns>
        public static bool IsEqualTo(this SecureString ss1, SecureString ss2)
        {
            IntPtr bstr1 = IntPtr.Zero;
            IntPtr bstr2 = IntPtr.Zero;
            try
            {
                bstr1 = Marshal.SecureStringToBSTR(ss1);
                bstr2 = Marshal.SecureStringToBSTR(ss2);
                var length1 = Marshal.ReadInt32(bstr1, -4);
                var length2 = Marshal.ReadInt32(bstr2, -4);
                if (length1 != length2)
                    return false;

                for (int x = 0; x < length1; x += 2)
                {
                    var b1 = Marshal.ReadInt16(bstr1, x);
                    var b2 = Marshal.ReadInt16(bstr2, x);
                    if (b1 != b2) return false;
                }

                return true;
            }
            finally
            {
                if (bstr2 != IntPtr.Zero) Marshal.ZeroFreeBSTR(bstr2);
                if (bstr1 != IntPtr.Zero) Marshal.ZeroFreeBSTR(bstr1);
            }
        }
    }
}
