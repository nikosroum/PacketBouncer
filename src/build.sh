#!/bin/bash
##########################################################################
# Script for building/compiling the bouncer applications in course ik2213.
# Note to students: you will have to adapt your application to this script
# The script name must not be changed, no parameters will be set.
# Tip: use comand 'export' if you need to set environment variables.
# Tip: use a makefile or ant for building.
# -----------------------------------------------------------------------
# 2009-05-08 Dan Kopparhed dank@kth.se
##########################################################################
THISFILE=${0##*/}
PID=$$
##########################################################################
#export ANT_OPTS=-Xmx64m
#ant clean
#ant jar
#javac -J-Xmx64m Bouncer.java

make

exit 0
