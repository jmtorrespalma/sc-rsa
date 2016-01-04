#!/bin/bash
ls doc.* | grep -v *.tex | grep -v *.pdf | xargs rm
