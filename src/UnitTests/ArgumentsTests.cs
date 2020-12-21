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
