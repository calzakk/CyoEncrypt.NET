// [CyoEncrypt.NET] ArgumentTests.cs

// The MIT License (MIT)

// Copyright (c) 2020-2021 Graham Bull

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

using CyoEncrypt;
using FluentAssertions;
using System;
using Xunit;

namespace UnitTests
{
    public class ArgumentsTests
    {
        [Fact]
        public void WhenNothingSpecified_WhenTheArgumentsAreParsed_ThenNoArgumentsShouldBeFlagged()
        {
            var args = Arguments.Parse(Array.Empty<string>());

            args.Help.Should().BeFalse();
            args.Recurse.Should().BeFalse();
            args.NoConfirm.Should().BeFalse();
            args.Pathname.Should().BeNull();
            args.Password.Should().BeNull();
        }

        [Theory]
        [InlineData("-?")]
        [InlineData("-h")]
        [InlineData("--help")]
        public void GivenHelpIsSpecified_WhenTheArgumentsAreParsed_ThenHelpShouldBeFlagged(string arg)
        {
            var args = Arguments.Parse(new[] { arg });

            args.Help.Should().BeTrue();
            args.Recurse.Should().BeFalse();
            args.NoConfirm.Should().BeFalse();
            args.Pathname.Should().BeNull();
            args.Password.Should().BeNull();
        }

        [Theory]
        [InlineData("-r")]
        [InlineData("--recurse")]
        public void GivenRecurseIsSpecified_WhenTheArgumentsAreParsed_ThenRecurseShouldBeFlagged(string arg)
        {
            var args = Arguments.Parse(new[] { arg });

            args.Help.Should().BeFalse();
            args.Recurse.Should().BeTrue();
            args.NoConfirm.Should().BeFalse();
            args.Pathname.Should().BeNull();
            args.Password.Should().BeNull();
        }

        [Theory]
        [InlineData("--no-confirm")]
        public void GivenNoConfirmIsSpecified_WhenTheArgumentsAreParsed_ThenNoConfirmShouldBeFlagged(string arg)
        {
            var args = Arguments.Parse(new[] { arg });

            args.Help.Should().BeFalse();
            args.Recurse.Should().BeFalse();
            args.NoConfirm.Should().BeTrue();
            args.Pathname.Should().BeNull();
            args.Password.Should().BeNull();
        }

        [Fact]
        public void GivenPathnameIsSpecified_WhenTheArgumentsAreParsed_ThenPathnameShouldBeFlagged()
        {
            var args = Arguments.Parse(new[] { "/path/to/file" });

            args.Help.Should().BeFalse();
            args.Recurse.Should().BeFalse();
            args.NoConfirm.Should().BeFalse();
            args.Pathname.Should().Be("/path/to/file");
            args.Password.Should().BeNull();
        }

        [Fact]
        public void GivenPathnameAndPasswordAreSpecified_WhenTheArgumentsAreParsed_ThenPathnameAndPasswordShouldBeFlagged()
        {
            var args = Arguments.Parse(new[] { "/path/to/file", "12345" });

            args.Help.Should().BeFalse();
            args.Recurse.Should().BeFalse();
            args.NoConfirm.Should().BeFalse();
            args.Pathname.Should().Be("/path/to/file");
            args.Password.Should().Be("12345");
        }

        [Fact]
        public void GivenThreeStringsAreSpecified_WhenTheArgumentsAreParsed_ThenAnExceptionShouldBeThrown()
        {
            Action action = () => Arguments.Parse(new[] { "/path/to/file", "12345", "67890" });
            action.Should().Throw<ArgumentException>();
        }
    }
}
