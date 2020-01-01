ArgX - Better argument passing for Windows
==========================================

.. image:: https://travis-ci.org/al45tair/ArgX.svg?branch=master
    :target: https://travis-ci.org/al45tair/ArgX

Introduction
------------

Windows' handling of command line arguments historically has been
poor; even in 2019, Windows still passes arguments as a single command
line string, which makes processing arguments error-prone and also
results in unreasonable limits on command line lengths.

ArgX aims to fix this situation in a backwards-compatible manner, such
that programs that use ArgX will be able to pass arbitrary numbers of
arguments cleanly among themselves without worrying about how various
metacharacters might be interpreted by subprocesses.
