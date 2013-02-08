Hogments - Pygments lexer for Snort rules
=========================================

A quick hack to get [Snort][] support in [Pygments][].

As it stands it's probably not very pretty output wise, nor code wise.

To test:

    python hogments/hog.py filename.rules

To install:

    sudo python setup.py install

If this fails because you previously installed this lexer and have pulled a new
revision where I have not incremented the version number in setup.py, you can
try appending the --force option to setup.py.

After that it should be possible to use it with pygmentize:

    pygmentize -f 256 filename.rules
    pygmentize -f 256 -l hog filename.rules
    pygmentize -f 256 -l snort filename.rules


List of keywords and the test file has been lifted without shame from
BobuSumisu's [snort-mode repository][snort-mode].

[Pygments]: http://pygments.org/docs/plugins/
[Snort]: http://www.snort.org/
[snort-mode]: https://github.com/BobuSumisu/snort-mode/
