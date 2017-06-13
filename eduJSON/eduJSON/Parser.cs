/*
    eduJSON - A Lightweight JSON Parser for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;

namespace eduJSON
{
    /// <summary>
    /// JSON parser
    /// </summary>
    public class Parser
    {
        /// <summary>
        /// Parses the input JSON string <paramref name="str"/> and builds an object tree representing JSON data.
        /// </summary>
        /// <param name="str">The JSON string to parse</param>
        /// <returns>An object representing JSON data</returns>
        public static object Parse(string str)
        {
            int idx = 0;

            // Skip leading spaces and comments.
            SkipSpace(str, ref idx);

            // Parse the root value.
            object obj = ParseValue(str, ref idx);

            // Skip trailing spaces and comments.
            SkipSpace(str, ref idx);
            if (idx < str.Length)
            {
                // Trailing data found.
                throw new ArgumentException(String.Format(Resources.ErrorTrailingData, GetShortened(str, idx)), "str");
            }

            return obj;
        }

        /// <summary>
        /// Parses the value encoded as JSON string <paramref name="str"/>.
        /// </summary>
        /// <param name="str">The JSON string to parse</param>
        /// <param name="idx">Starting index in <paramref name="str"/></param>
        /// <returns>An object representing JSON value</returns>
        protected static object ParseValue(string str, ref int idx)
        {
            if (ParseKeyword(str, ref idx, "true"))
            {
                // A logical value "true" was found.
                return true;
            }

            if (ParseKeyword(str, ref idx, "false"))
            {
                // A logical value "false" was found.
                return false;
            }

            if (ParseKeyword(str, ref idx, "null"))
            {
                // A "null" was found.
                return null;
            }

            {
                object obj = ParseNumber(str, ref idx);
                if (obj != null)
                    return obj;
            }

            {
                object obj = ParseString(str, ref idx);
                if (obj != null)
                    return obj;
            }

            switch (str[idx])
            {
                case '[':
                    {
                        // A table was found.
                        int startat_origin = idx;
                        List<object> obj = new List<object>();
                        bool is_empty = true, has_separator = false;

                        for (idx++; idx < str.Length;)
                        {
                            // Skip leading spaces and comments.
                            SkipSpace(str, ref idx);

                            if (idx < str.Length && str[idx] == ']')
                            {
                                // This is the end.
                                idx++;
                                return obj;
                            }
                            else if (is_empty || has_separator)
                            {
                                // Analyse value recursively, and add it.
                                obj.Add(ParseValue(str, ref idx));
                                is_empty = false;

                                // Skip trailing spaces and comments.
                                SkipSpace(str, ref idx);

                                if (idx < str.Length && str[idx] == ',')
                                {
                                    // A separator has been found. Skip it.
                                    idx++;
                                    has_separator = true;
                                }
                                else
                                    has_separator = false;
                            }
                            else
                                throw new ArgumentException(String.Format(Resources.ErrorMissingSeparatorOrClosingParenthesis, GetShortened(str, idx), "]"), "str");
                        }

                        throw new ArgumentException(String.Format(Resources.ErrorMissingClosingParenthesis, GetShortened(str, startat_origin), "]"), "str");
                    }

                case '{':
                    {
                        // An object has been found.
                        int startat_origin = idx;
                        Dictionary<string, object> obj = new Dictionary<string, object>();
                        bool is_empty = true, has_separator = false;

                        for (idx++; idx < str.Length;)
                        {
                            // Skip leading spaces and comments.
                            SkipSpace(str, ref idx);

                            if (idx < str.Length && str[idx] == '}')
                            {
                                // This is the end.
                                idx++;
                                return obj;
                            }
                            else if (is_empty || has_separator)
                            {
                                object key = ParseIdentifier(str, ref idx);
                                if (key != null)
                                {
                                    // An element key has been found.
                                    if (obj.ContainsKey((string)key))
                                        throw new ArgumentException(String.Format(Resources.ErrorDuplicateElement, (string)key), "str");

                                    // Skip trailing spaces and comments.
                                    SkipSpace(str, ref idx);

                                    if (idx < str.Length && str[idx] == ':')
                                    {
                                        // An key:value separator found.
                                        idx++;

                                        // Skip leading spaces and comments.
                                        SkipSpace(str, ref idx);

                                        // Analyse value recursively, and add it.
                                        obj.Add((string)key, ParseValue(str, ref idx));
                                        is_empty = false;

                                        // Skip trailing spaces and comments.
                                        SkipSpace(str, ref idx);

                                        if (idx < str.Length && str[idx] == ',')
                                        {
                                            // A separator has been found. Skip it.
                                            idx++;
                                            has_separator = true;
                                        }
                                        else
                                            has_separator = false;
                                    }
                                    else
                                        throw new ArgumentException(String.Format(Resources.ErrorMissingSeparator, GetShortened(str, idx)), "str");
                                }
                                else
                                    throw new ArgumentException(String.Format(Resources.ErrorInvalidIdentifier, GetShortened(str, idx)), "str");
                            }
                            else
                                throw new ArgumentException(String.Format(Resources.ErrorMissingSeparatorOrClosingParenthesis, GetShortened(str, idx), "}"), "str");
                        }
                        throw new ArgumentException(String.Format(Resources.ErrorMissingClosingParenthesis, GetShortened(str, startat_origin), "}"), "str");
                    }
            }

            throw new ArgumentException(String.Format(Resources.ErrorUnknownValue, GetShortened(str, idx)), "str");
        }

        /// <summary>
        /// Parses the constant value <paramref name="keyword"/> encoded as JSON string <paramref name="str"/>. Used for parsing "true", "false" and "null" values.
        /// </summary>
        /// <param name="str">The JSON string to parse</param>
        /// <param name="idx">Starting index in <paramref name="str"/></param>
        /// <param name="keyword">Expected keyword. Should be all-lowercase.</param>
        /// <returns><c>true</c> when JSON string <paramref name="str"/> at <paramref name="idx"/> matches the keyboard <paramref name="keyword"/>; <c>false</c> otherwise.</returns>
        /// <remarks>The JSON string <paramref name="str"/> is converted to lowercase for matching only. Therefore <paramref name="keyword"/> should be given all-lowercase.</remarks>
        protected static bool ParseKeyword(string str, ref int idx, string keyword)
        {
            int len = keyword.Length;

            if (idx + len <= str.Length && str.Substring(idx, len).ToLower() == keyword)
            {
                // Keyword found. Check that non-identifier character follows.
                int i = idx + len;
                if (i >= str.Length || (!char.IsLetterOrDigit(str[i]) && str[i] != '_'))
                {
                    idx += len;
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Parses the integer or floating number encoded as JSON string <paramref name="str"/>.
        /// </summary>
        /// <param name="str">The JSON string to parse</param>
        /// <param name="idx">Starting index in <paramref name="str"/></param>
        /// <returns>The number of type <code>int</code> or <code>double</code> (depending on JSON string <paramref name="str"/> at <paramref name="idx"/>); or <c>null</c> if not-a-number.</returns>
        protected static object ParseNumber(string str, ref int idx)
        {
            int i = idx, n = str.Length;

            if (i < n)
            {
                bool positive;
                if (str[i] == '-')
                {
                    // The number is negative.
                    positive = false;
                    i++;
                }
                else if (str[i] == '+')
                {
                    // JSON EXT: Explicit positive sign
                    positive = true;
                    i++;
                }
                else
                {
                    // We are positive by default. :)
                    positive = true;
                }

                if (i < n)
                {
                    uint value;
                    if (str[i] == '0')
                    {
                        // The integer part is 0.
                        value = 0;
                        i++;
                    }
                    else if ('1' <= str[i] && str[i] <= '9')
                    {
                        value = (uint)(str[i] - '0');
                        i++;

                        // Parse rest of the number.
                        for (; i < n && '0' <= str[i] && str[i] <= '9'; i++)
                            value = value * 10 + (uint)(str[i] - '0');
                    }
                    else
                        return null;

                    double value_f = value;
                    bool is_f = false;

                    if (i < n && str[i] == '.')
                    {
                        // Digital part.
                        i++;
                        if (i < n && '0' <= str[i] && str[i] <= '9')
                        {
                            uint c = 10, digital = (uint)(str[i] - '0');
                            i++;

                            // Parse the digital part.
                            for (; i < n && '0' <= str[i] && str[i] <= '9'; i++)
                            {
                                digital = digital * 10 + (uint)(str[i] - '0');
                                c *= 10;
                            }

                            value_f += (double)digital / c;
                            is_f = true;
                        }
                        else
                            return null;
                    }

                    if (i < n && (str[i] == 'E' || str[i] == 'e'))
                    {
                        // Exponential part.
                        i++;
                        bool e_positive;
                        if (str[i] == '-')
                        {
                            // The exponent will be negative.
                            e_positive = false;
                            i++;
                        }
                        else if (str[i] == '+')
                        {
                            // The exponent will be positive.
                            e_positive = true;
                            i++;
                        }
                        else
                        {
                            // Default exponent sign is positive.
                            e_positive = true;
                        }

                        if (i < n && '0' <= str[i] && str[i] <= '9')
                        {
                            int exp = (int)(str[i] - '0');
                            i++;

                            // Parse rest of the number.
                            for (; i < n && '0' <= str[i] && str[i] <= '9'; i++)
                                exp = exp * 10 + (int)(str[i] - '0');

                            value_f *= Math.Pow(10, e_positive ? exp : -exp);
                            is_f = true;
                        }
                        else
                            return null;
                    }

                    idx = i;
                    if (is_f)
                    {
                        // Return number as "double".
                        return positive ? value_f : -value_f;
                    }
                    else
                    {
                        // Return number as unsigned integer.
                        return positive ? (int)value : -(int)value;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Parses the string encoded as JSON string <paramref name="str"/>.
        /// </summary>
        /// <param name="str">The JSON string to parse</param>
        /// <param name="idx">Starting index in <paramref name="str"/></param>
        /// <returns>The string of type <code>string</code>; or <c>null</c> if JSON string <paramref name="str"/> at <paramref name="idx"/> does not represent a string.</returns>
        protected static object ParseString(string str, ref int idx)
        {
            int i = idx, n = str.Length;

            if (i < n && str[i] == '"')
            {
                // Opening quote found.
                i++;
                string res = "";
                for (; i < n; )
                {
                    char chr = str[i];
                    if (chr == '"')
                    {
                        // Closing quote found.
                        idx = i + 1;
                        return res;
                    }
                    else if (chr == '\\')
                    {
                        // Escape sequence found.
                        i++;
                        switch (str[i])
                        {
                            case '"': res += '"'; i++; break;
                            case '\\': res += '\\'; i++; break;
                            case '/': res += '/'; i++; break;
                            case 'b': res += '\b'; i++; break;
                            case 'f': res += '\f'; i++; break;
                            case 'n': res += '\n'; i++; break;
                            case 'r': res += '\r'; i++; break;
                            case 't': res += '\t'; i++; break;
                            case 'u':
                                i++;
                                uint unicode = 0;
                                for (uint count = 0; count < 4 && i < n; i++, count++)
                                {
                                    chr = str[i];
                                    if ('0' <= chr && chr <= '9')
                                        unicode = unicode * 16 + (uint)(chr - '0');
                                    else if ('a' <= chr && chr <= 'f')
                                        unicode = unicode * 16 + (uint)(chr - 'a') + 10;
                                    else if ('A' <= chr && chr <= 'F')
                                        unicode = unicode * 16 + (uint)(chr - 'A') + 10;
                                    else
                                    {
                                        // JSON EXT: Shorter than 4-hexadecimal Unicode codes
                                        break;
                                    }
                                }
                                res += (char)unicode;
                                break;

                            default:
                                // JSON EXT: Ignore invalid escape sequence
                                res += '\\';
                                res += str[i]; i++;
                                break;
                        }
                    }
                    else
                    {
                        // JSON EXT: Control characters in strings
                        res += chr; i++;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Parses the field identifier encoded as JSON string <paramref name="str"/>.
        /// </summary>
        /// <param name="str">The JSON string to parse</param>
        /// <param name="idx">Starting index in <paramref name="str"/></param>
        /// <returns>The string of type <code>string</code>; or <c>null</c> if JSON string <paramref name="str"/> at <paramref name="idx"/> does not represent an identifier.</returns>
        protected static object ParseIdentifier(string str, ref int idx)
        {
            int i = idx, n = str.Length;

            if (i < n && str[i] == '"')
            {
                // Identifier is encoded as quoted string.
                return ParseString(str, ref idx);
            }
            else
            {
                // JSON EX: Non-quoted identifiers
                for (; i < n && (char.IsLetterOrDigit(str[i]) || str[i] == '_'); i++) ;

                if (idx < i)
                {
                    string res = str.Substring(idx, i - idx);
                    idx = i;
                    return res;
                }
            }

            return null;
        }

        /// <summary>
        /// Skips white-space between JSON values.
        /// </summary>
        /// <param name="str">The JSON string to parse</param>
        /// <param name="idx">Starting index in <paramref name="str"/></param>
        /// <remarks>C/C++ style comments are also treated as white-space and skipped.</remarks>
        protected static void SkipSpace(string str, ref int idx)
        {
            for (int len = str.Length; idx < len;)
            {
                if (char.IsWhiteSpace(str[idx]))
                {
                    // Skip whitespace.
                    idx++;
                }
                else if (idx + 1 < len && str[idx] == '/')
                {
                    // JSON EXT: C/C++ style comments
                    if (str[idx + 1] == '/')
                    {
                        // C++ line comment. Skip anything up to the line-break.
                        for (idx += 2; ;)
                        {
                            if (idx >= len)
                                break;
                            else if (str[idx] == '\n')
                            {
                                idx++;
                                break;
                            }
                            else
                                idx++;
                        }
                    }
                    else if (str[idx + 1] == '*')
                    {
                        // C comment. Skip anything until "*/".
                        for (idx += 2; ;)
                        {
                            if (idx >= len)
                                break;
                            else if (idx + 1 < len && str[idx] == '*' && str[idx + 1] == '/')
                            {
                                idx += 2;
                                break;
                            }
                            else
                                idx++;
                        }
                    }
                    else
                        break;
                }
                else
                    break;
            }
        }

        /// <summary>
        /// Returns maximum 20 characters of the input string from given location.
        /// If remainder of the string is longer than 20 characters, 19 characters are kept with horizontal ellipsis appended.
        /// </summary>
        /// <param name="str">The input string</param>
        /// <param name="idx">Starting index in <paramref name="str"/></param>
        /// <returns>Truncated string</returns>
        protected static string GetShortened(string str, int idx)
        {
            return str.Length < idx + 20 ? str.Substring(idx) : str.Substring(idx, 19) + "…";
        }
    }
}
