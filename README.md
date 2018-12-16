# Overview
This software evolved from Felix Leder’s RE-Google python script for IDA Pro. 

RE-Google did 2 things:
- Traverse IDAs known functions and for each make a list of constants, strings and function call names (search terms)
- Submit each list to Google Code Search (GCS)via a Google API, and add the most relevant results to the comment header of the associated function.

GCS is dead and buried, but the idea of trying to find a close source code match for a disassembled function is still a good one. Google was kind enough to open source the indexer it used for GCS at:
https://code.google.com/p/codesearch/ 

## Details
RE-Source reuses the string extraction code from Re-Google (with the addition of some demangling) and replaces the search handling part with codesearch. The regular expressions that codesearch understands are very limited. Google did not open source the glue that turns a search string into something that can be fed to the indexer. Hence that part had to be rewritten.

After some experimentation, the following is the current method. For each function:
1. Extract search terms (constants, APIs, strings). Demangle APIs if possible/appropriate.
2. Call the codesearch for each search term. Store list of matching filenames in a set per term.
3. Determine the file name that matches the greatest number of search terms, in the hope that this is the file most likely to contain a function that approximates the disassembled one.
4. Return (into the function comment) the largest combinatorial set of matching search terms
5. Return (into the function comment) remaining search terms matching in a smaller combinatorial sets
6. Return (into the function comment) search terms which did not yield any result.

So this way, if we find a match for 8 out of 10 terms, we may still hit on source code for a previous version of the binary.

### Example

Lets test this on an open source twapi library. Install the codesearch program such that csearch.exe  resides in c:\codesearch (still hard coded at this time; should probably add an option to pass the codesearch location). Make that your current directory.

Next download the source code with mercurial ( or get it any other way you like)

hg clone http://hg.code.sf.net/p/twapi/twapi31 twapi-twapi31 

Now c:\codesearch\twapi-twapi31 contains the source code

Execute 

cindex.exe twapi-twapi31

This will make an index from the twapi source so that csearch.exe can do its job.

Then get the prebuilt dll from sourceforge:

http://sourceforge.net/projects/twapi/files/Current%20Releases/Tcl%20Windows%20API/twapi-3.1.17/

This is a case where the dll is built with debug information and has an overbundance of possible search terms. 

An example result is this:

!(image1.jpg)

Ok, so sub_1000BE73 does not have a public name, which would normally make it tricky to find in a source base. However, we have a high confidence match based on the function calls made in the subroutine. In this case only one file matches all the search terms, clipboard.c. A quick look at clipboard.c yields:

!(image2.jpg)

Which is the proper function. It this point we could carefully provide IDA with type information etc...

RE-Source annotated 269 out of 718 functions, and took 2 minutes on an i7-3517U processor. There is some room for improvement. For example, fairly long strings (with at least a space) should probably get a higher priority than function calls or constants. A string like “Could not query terminal session information.” is more valuable in finding the file of interest than the fact that GetLastError was called.

Another idea would be to run an information gathering plugin such as Sirmabus’ GUID-Finder, and include the results in the search. This may be added in the future. Of course, there are also online search engines similar to the deprecated GCS, and RE-Source could be extended to look there too.

