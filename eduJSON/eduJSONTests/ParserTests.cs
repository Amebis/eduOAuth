/*
    eduJSON - A Lightweight JSON Parser for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;

namespace eduJSON.Tests
{
    [TestClass()]
    public class ParserTests
    {
        [TestMethod()]
        public void ParseTestBoolean()
        {
            // Test basic data types.
            Assert.AreEqual(true, Parser.Parse("// Test 1\n  True /* Trailing comment */"), "Boolean \"true\" not recognized");
            Assert.AreEqual(false, Parser.Parse("   falSe\r\n// Trailing comment"), "Boolean \"false\" not recognized");
        }

        [TestMethod()]
        public void ParseTestNull()
        {
            Assert.AreEqual(null, Parser.Parse("NULL"), "\"null\" not recognized");
        }

        [TestMethod()]
        public void ParseTestInteger()
        {
            Assert.AreEqual(1234, Parser.Parse(" 1234 "), "Integer not recognized");
            Assert.AreEqual(1234, Parser.Parse(" +1234 "), "Integer with an explicit \"+\" sign not recognized (JSON EX)");
            Assert.AreEqual(-1234, Parser.Parse(" -1234 "), "Negative integer not recognized");
        }

        [TestMethod()]
        public void ParseTestFloat()
        {
            Assert.AreEqual(1.0870e-3, (double)Parser.Parse(" +1.0870e-3 "), 1e-10, "Float not recognized");
            Assert.AreEqual(-2e+31, (double)Parser.Parse(" -2e+31 "), 1e-10, "Negative float not recognized");
        }

        [TestMethod()]
        public void ParseTestString()
        {
            Assert.AreEqual("This is a test.", Parser.Parse(" \"This is a test.\" "), "Quoted string not recognized");
            Assert.AreEqual("  \"/\\\b\f\n\r\t\u263a\\x  ", Parser.Parse(" \"  \\\"\\/\\\\\\b\\f\\n\\r\\t\\u263A\\x  \" "), "JSON string escape sequences not recognized");
        }

        [TestMethod()]
        public void ParseTestStruct()
        {
            // CollectionAssert.AreEqual() does not work for sub-collections; Check manually.
            object obj = Parser.Parse("{ \"key1\" : true , \"key2\" : [ 1, 2, 3, 4, 5], \"key3\" : { \"k1\": \"test1\", k2:\"test2\"}}");
            Dictionary<string, object> obj_dict = (Dictionary<string, object>)obj;
            Assert.AreEqual(3, obj_dict.Count, "Incorrect number of child elements");
            Assert.AreEqual(true, obj_dict["key1"], "Child element mismatch");
            CollectionAssert.AreEqual(new List<object>
                {
                    1,
                    2,
                    3,
                    4,
                    5
                }, (List<object>)obj_dict["key2"], "Child element mismatch");
            CollectionAssert.AreEqual(new Dictionary<string, object>
                {
                    { "k1", "test1" },
                    { "k2", "test2" }
                }, (Dictionary<string, object>)obj_dict["key3"], "Child element mismatch");

            try
            {
                Parser.Parse("[1, 2");
                Assert.Fail("Missing \"[\" parenthesis tolerated");
            }
            catch (ArgumentException) { }
            try
            {
                Parser.Parse("[1 2]");
                Assert.Fail("Missing separator tolerated");
            }
            catch (ArgumentException) { }
            try
            {
                Parser.Parse("{ \"k1\": 1, \"k2\": 2");
                Assert.Fail("Missing \"}\" parenthesis tolerated");
            }
            catch (ArgumentException) { }
            try
            {
                Parser.Parse("{ \"k1\": 1 \"k2\": 2 }");
                Assert.Fail("Missing separator tolerated");
            }
            catch (ArgumentException) { }
            try
            {
                Parser.Parse("{ \"k1\": 1, $$$: 2 }");
                Assert.Fail("Invalid identifier tolerated");
            }
            catch (ArgumentException) { }
            try
            {
                Parser.Parse("{ \"k1\": 1, \"k1\": 2 }");
                Assert.Fail("Duplicate key tolerated");
            }
            catch (ArgumentException) { }
        }

        [TestMethod()]
        public void ParseTestIssues()
        {
            try
            {
                Parser.Parse("   false\r\nTrailing data");
                Assert.Fail("Trailing JSON data tolerated");
            } catch (ArgumentException) {}
            try
            {
                Parser.Parse("abc");
                Assert.Fail("Unknown JSON value tolerated");
            }
            catch (ArgumentException) { }
        }
    }
}