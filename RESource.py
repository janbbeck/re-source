#!/usr/bin/python
########################################################################
# Copyright (c) 2009, Felix Leder <leder<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
# Originally called RE-Google
########################################################################
# Modified to RE-Source by Jan Beck 2013
#  removed google code search API - RIP!
#  added demangling
#  added local codesearch
#  added partial match algorithm to return highest confidence match
#     
########################################################################
# Description:
#   code search to identify known functions
#
# Status: Ready
#
########################################################################
#
#  This file is RE-Source
#
#  RE-Source is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
########################################################################

"""RE-Source

Performs a code search for each function based on the contained
 - strings
 - constants / immedite values
 - import names
"""

import cProfile
import sys
import time
import subprocess
import idaapi
import idautils
import idc
import time
#import wingdbstub
import collections

######################### Configuration #####################


#search all functions or just the one at the cursor?
# use True or False
SEARCH_ALL_FUNCTIONS = True


#flag whether to skip functions already having processed function comments
# this flag can be used to continue analysis after an interruption
# use True or False
SKIP_PROCESSED_FUNCTIONS = False

# some results fit to many queries but don't tell anything
#   you can blacklist those here based on suffix or containing
BLACKLIST_SUFFIX = [ "winbase.h" , "jclwin32.pas"]
BLACKLIST_CONTAIN = [ "/wine", "/winbase" ]

# also have a look at the constant_filter function that
#  restricts the immediate values to search for


# Added comments are prefixed with the following
RESULT_PREFIX = "RE-Source: "


########################### Constants #######################

DIRECTION_FORW = 0x03
BADADDR = idaapi.BADADDR


########################### Globals #########################

CACHE = {}

IDATA_SEGMENTS = []



###################### Filter functions ###################3

def title_blacklisted(title):
    """Checks if parts of the given (google result) title should be blacklisted.
    This is especially usefull for wine and windows header because those find
    almost all important constants

    @parm title: Google search result title
    @type title: str
    @return: C{True} if blacklisted. C{False} otherwise
    """
    ltit = title.lower()

    for b_el in BLACKLIST_SUFFIX:
        if ltit.endswith(b_el):
            return True

    for b_el in BLACKLIST_CONTAIN:
        if ltit.lower().find(b_el) >= 0:
            return True

    return False


def constant_filter(value):
    """Filter for certain constants/immediate values. Not all values should be
    taken into account for searching. Especially not very small values that
    may just contain the stack frame size.

    @param value: constant value
    @type value: int
    @return: C{True} if value should be included in query. C{False} otherwise
    """
    # no small values
    if value < 0x10000:
        return False
    if value & 0xFFFFFF00 == 0xFFFFFF00 or \
       value & 0xFFFF00 == 0xFFFF00:
        return False
    #no single bits sets - mostly defines / flags
    for i in xrange(32):
        if value == (1 << i):
            return False

    return True


def sanitize_name(name):
    """Sanitize name for Windows:
    Remove trailing A or W
    Remove preceeding "_"

    @param name: import name to be sanitized
    @type name: str
    @return: sanitized named
    """
    name = name.strip()
    if name.endswith("A"):
        name = name[:-1]
    elif name.endswith("W"):
        name = name[:-1]
    while name.startswith("_"):
        name = name[1:]

    return name


######################## Main functionality #########################

def search4files(searchstring, numoffiles=5):
    """Perform the google code search
    @param searchstring: The terms to be searched for
    @type searchstring: str
    @param numoffiles: Number of results to return
    @type numoffiles: int
    @param maxthreshold: int
    @return: top 5 results
    """
    comment = ""
    # make list of items to search for
    matchingfiles = set()
    splitstring = searchstring.split("\" \"")                # ["blah blac","boo boo","hahh aha"]
    splitstring = sorted(splitstring, key=len, reverse=True) # I am making the assumption that longer strings are more interesting for the purpose of limiting search terms in the next line
    splitstring = splitstring[:100]                          # limit number of search terms; 100 is quite large already
    for index, item in enumerate(splitstring): 
        splitstring[index] = re.sub('["]', '', item)         # removing double quotes from search terms as that would upset the search string
    setlist = []                                             # create list of sets
    for index, item in enumerate(splitstring):               # for each serch term, do
        matchingfiles = set()                                       # create a set of paths matching current query string
        try:
            output = subprocess.check_output("c:/codesearch/csearch.exe " + '"' + item + '"' , shell=True, stderr=subprocess.STDOUT)
        except Exception, e:
            output = str(e.output)	# csearch returns 1 on success, but python thinks that is an error....
        if output:
            for line in output.split('\n'):
                outsplit = line.split(':',2)  #split file paths from output
                matchingfiles.add(':'.join(outsplit[:2]))		
            setlist.append( (matchingfiles,item))            # add a set of all paths matching current search	    
    if setlist:   
        newlist = []
        for index, line in enumerate(setlist): # newlist is a list of all the files in setlist
            for line2 in list(line[0]):
                newlist.append(line2)
        newlist = [x for x in newlist if x]          # strip empties
        a = collections.Counter(newlist)             # count occurences of files; the most common one is the one most search terms match; we'll build a set of those terms
        b = a.most_common()                          # create list; sorted by occurance
        c = b[0]                                     # grab first tuple; highest occurance
        mostCommonFileName = str(c[0])               # snag filename from tuple 
        icount= 0                                    # count number of search terms matching most common filename
        totalNumberOfSearchTerms = len(splitstring)  # count total number of search terms                       
        matchingterms = set()
        nonmatchingterms = set()
        matchingnames = set()
        first = 1
        for index, line in enumerate(setlist):
            g = setlist[index]
            if mostCommonFileName in g[0]:
                icount += 1                     # count number of search terms matching most common filename
                matchingterms.add(g[1])
                if first:
                    matchingnames = g[0]
                    first = 0
                else:
                    matchingnames = matchingnames & g[0]
            else:
                nonmatchingterms.add(g[1])
        if "" in matchingterms:                       #clean out empties
            matchingterms.remove("")
        if "" in nonmatchingterms:                    #clean out empties
            nonmatchingterms.remove("")               
        if "" in matchingnames:                       #clean out empties
            matchingnames.remove("")                  
        missedSearchTerms = (set(splitstring) - matchingterms) - nonmatchingterms
        
        #print out our findings
        comment = comment + "Largest combinatorial set of matching search terms: \n"
        for index, line in enumerate(matchingterms):
            if index == numoffiles:
               comment = comment + "\nand more ... (" + str(len(matchingterms)) + " total)\n"
               break
            comment = comment + line +'\n'
        comment = comment + "\n\nRemaining search terms matching in a smaller combinatorial set: \n"
        for index, line in enumerate(nonmatchingterms): 
            if index == numoffiles:
               comment = comment + "\nand more ... (" + str(len(nonmatchingterms)) + " total)\n"
               break
            comment = comment + line +'\n'                    
        comment = comment + "\nFiles matching:\n"
        for index, line in enumerate(matchingnames): 
            if index == numoffiles:
               comment = comment + "\nand more ... (" + str(len(matchingnames)) + " total)\n"
               break
            comment = comment + line +'\n'          
        comment = comment + "\nSearch terms not found : \n"
        for index, line in enumerate(missedSearchTerms): 
            if index == numoffiles:
               comment = comment + "\nand more ... (" + str(len(missedSearchTerms)) + " total)\n"
               break
            comment = comment + line +'\n'         
        comment = comment + "\nMatching:"+str(100*icount/totalNumberOfSearchTerms)+"% ("+str(icount)+" search terms out of "+str(totalNumberOfSearchTerms)+")"
    else:
        comment = ""
    return comment


def query4function(func):
    """Examine this function, extract constants, strings, imports and generate
    query.
    @param func: Function to examine
    @type func: functions object
    """
    constants = []
    strlist = []
    implist = set()

    assert( func )    

    if SKIP_PROCESSED_FUNCTIONS:
        cmt = func.get_comment()
        if cmt and RESULT_PREFIX in cmt:
            #print "Skipping function: %s" % func.get_name()
            return True


    for inst in func.get_instructions():
        for oper in inst.get_operands():
            # constants
            val = oper.get_immediate()
            if val and constant_filter(val):
                constants.append("0x%x" % val)

            #strings
            soper = oper.get_string()            
            if soper:
                soper = soper.replace('"','').strip()
                if len(soper)>0:
                    strlist.append('"%s"' % soper)

            #imports
            coderefs = inst.get_code_refs_from()
            for ref in coderefs:
                # call/jump to import segment?
                if len([start for (start, end) in IDATA_SEGMENTS \
                        if start <= ref <= end]) > 0:
                    # yes, we have an import
                    name = idaapi.get_name(inst.iea, ref)
                    if name:
                        implist.add( sanitize_name(name) )


    res = ""
    # 1. try full match
    implist = list(implist)
    for i in xrange(len(implist)):
        implist[i] = '"' + implist[i]   + '"'
    constants = list(constants)
    for i in xrange(len(constants)):
        constants[i] = '"' + constants[i]   + '"'	
    fulllist = constants + strlist
    if len(fulllist)>0 or len(implist)>2:
        fulllist += implist
        l = " ".join(fulllist)
        #print "list:", l
        res = search4files( l )
    """
    # 2. try just strings if unsuccessful
    if len(res) == 0 and len(strlist)>0:
        res = search4files( " ".join(strlist) )
    # 3. try just constants if unsuccessful
    if len(res) == 0 and len(constants)>0:
        res = search4files( " ".join(constants) )
    """
    res = prefix_lines(res)        
    if len(res) > 0:
        cmt = remove_prefixed_lines( func.get_comment() )
        if not cmt:                
            func.set_comment(res)
        else:
            #func.set_comment(res)
            func.set_comment(cmt + "\n" + res)
        print "Successfull for function: %s @ address\n0x%x" % \
              (func.get_name(), func.start_ea)
        return True

    return False



def re_source(all_funcs = True):
    """Start the analysis
    @param all_funcs: Indicates whether all or just the function under the
                      cursor are to be investigated
    @type all_funcs: bool
    """
    print "\n\n------- Starting..... --------"

    success = 0   #number of successfull function counter

    if not all_funcs:
        func = Function( idaapi.get_screen_ea() )
        if query4function(func):
            success += 1
        func_count = 1
    else:
        func_eas = get_all_function_eas()

        # init progress counter
        progress = 0
        func_count = len(func_eas)

        for i in xrange(func_count):            
            percentage = 10*i / func_count
            if  percentage > progress:
                print "------------- Progress Status : %i%%" % (percentage * 10)
                progress = percentage

            func = Function( func_eas[i] )
#            print "Looking at function  ", func.get_name() 
#	    print "Looking at demangled1", idc.Demangle(func.get_name(),idc.GetLongPrm(INF_SHORT_DN))
#	    print "Looking at demangled2", idc.Demangle(func.get_name(),idc.GetLongPrm(INF_LONG_DN))
            if query4function(func):
                success += 1

    print "%i snippets found (out of %i functions)" % (success, func_count)
    print "Done"





###################### helper functions ##############################


def prefix_lines(lines):
    """Prefixes the given lines with the RESULT_PREFIX defined above
    @param lines: Result string (normally multiple lines)
    @type lines: str
    @return: String in which each line is prefixed
    """
    if not lines or len(lines) == 0:
        return lines
    result = [RESULT_PREFIX+line for line in lines.splitlines()]

    return "\n".join(result)


def remove_prefixed_lines(lines):
    """Removes lines starting with the RESULT_PREFIX defined above
    @param lines: String containing multiple lines
    @type lines: str
    @return: String with all prefixed lines removed
    """
    if not lines or len(lines) == 0:
        return lines

    result = [line for line in lines.splitlines() \
              if not line.startswith(RESULT_PREFIX)]
    return "\n".join(result)


def get_all_function_eas():
    """Returns the start addresses of all functions identified by IDA
    @return: List of all functions' start addresses"""
    result = []

    for fnum in xrange(idaapi.get_func_qty()):
        func = idaapi.getn_func(fnum)
        f_ea = func.startEA
        if f_ea != BADADDR:
            result.append(f_ea)

    return result


def get_import_segments():
    """@return: List of all (start, end)-tuples for all import segments"""
    result = []

    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg.type == idaapi.SEG_XTRN:
            result.append( (seg.startEA, seg.endEA) )

    return result


def u2signed(num):
    """converts 32-bit (incorrectly) unsigned number into correct 32-bit
    signed format.
    @param num: A number
    @type num: int
    @return: signed representation
    """
    if num < 0x80000000:
        return num
    else:
        return num - 0x100000000


################################ functions object ##########################

class Function(object):
    """This object represents a function identified by IDA. It's main purpose
    is to encapsulate some of the often needed functionality into an object
    for ease of use."""

    def __init__(self, start_ea):
        """Initializes the function object
        @param start_ea: Start address of the function
        @type start_ea: int (ea)
        """
        self.start_ea = start_ea        


    def get_name(self):
        """Returns the name of the function.
        @return: Name of the considered function
        """
        thename = idaapi.get_func_name(self.start_ea)
        demangled = idc.Demangle(thename,idc.GetLongPrm(INF_SHORT_DN))
        if  demangled == None:
            return thename
        else:
            return demangled


    def get_instruction_eas(self):
        """Get the effective addresses (eas) for each instruction in the
        function.
        @return: List of eas pointing to the instruction starts inside function
        """
        result = []
        for chunk in self.__get_chunks():
            ins_ea = idc.FindCode(chunk.startEA-1, DIRECTION_FORW)
            while ins_ea <= chunk.endEA and ins_ea != BADADDR:
                result.append(ins_ea)
                ins_ea = idc.FindCode(ins_ea, DIRECTION_FORW)

        return result    


    def get_instructions(self):
        """Returns a list of insruction objects for each instruction.
        @return: List of instruction objects
        """
        return [Instruction(iea) for iea in self.get_instruction_eas()]


    def get_code_refs_from(self):
        """Returns the code refs originating from this function.
        @return: List of code references from this function
        """
        result = []
        for iea in self.get_instruction_eas():
            inst = Instruction(iea)
            result += inst.get_code_refs_from()

        return list(set(result))


    def get_data_refs_from(self):
        """Returns the data refs originating from this function.
        @return: List of data references from this function
        """
        result = []
        for iea in self.get_instruction_eas():
            inst = Instruction(iea)
            result += inst.get_data_refs_from()

        return list(set(result))

    def set_comment(self, comment, repeatable = False):
        """Sets a function comment.
        @param comment: The comment for this function
        @type comment: str
        @param repeatable: Flag if the comment is a repeatable comment
        @type repeatable: bool
        """
        func = self.__get_func_t()
        idaapi.set_func_cmt(func, comment, repeatable)


    def get_comment(self, repeatable = False):
        """Returns the comment for this function.
        @param repeatable: Flag whether to get repeatable comments or not
        @type repeatable: bool
        @return: The function comment"""
        func = self.__get_func_t()
        return idaapi.get_func_cmt(func, repeatable)


    def __get_chunks(self):
        """Internal Don't use.
        Returns the chunks of this function. Some functions are split into
        different memory blocks. This is caused e.g. by compiler optimzations
        (for space) or by obfuscation.
        @return: List of chunk areas (each having a start and end)
        """
        func = self.__get_func_t()
        result = [func]

        ft_iter = idaapi.func_tail_iterator_t(func, self.start_ea)
        if ft_iter.first():
            result.append(ft_iter.chunk())
        while ft_iter.next():
            result.append(ft_iter.chunk())

        return result

    def __get_func_t(self):
        """Internal function. Don't use.        
        Returns the func_t object to the current function. Unfortunately
        those structures are not persisent in IDA. Thus, they have to be
        queried for each usage.
        @return: func_t object for current function
        """        
        result = idaapi.get_func(self.start_ea)
        if not result:
            raise RuntimeError, \
                  "Cannot retrieve function information @ address %s" % \
                  self.start_ea

        return result

    def __repr__(self):
        return self.get_name()


################################ instruction object ##########################

class Instruction(object):
    """This object represents an instruction in IDA. Use it for convenience
    like the function object"""

    def __init__(self, inst_ea):
        """Initialize the instruction object.
        @param inst_ea: Address of the instruction
        @type inst_ea: int (ea)
        """
        self.iea = inst_ea


    def get_code_refs_from(self):
        """Returns the code refs originating from this instruction.
        @return: List of code references from this instruction
        """
        return idautils.CodeRefsFrom(self.iea, False) #don't follow flow


    def get_data_refs_from(self):
        """Returns the data refs originating from this instruction.
        @return: List of data references from this instruction
        """
        return idautils.DataRefsFrom(self.iea, False) #don't follow flow


    def get_operands(self):
        """Returns list of operand objects for the instruction
        @return: List of operand objects
        """
        result = []
        ins = self.__get_insn_t()
        if not ins:
            print >> sys.stderr, \
                  "Cannot retrieve operand information @ address %s" % \
                  hex(self.iea)
            return result

        for i in xrange(6):
            #oper = idaapi.get_instruction_operand(ins, i)
            oper = ins[i]
            if oper.type != idaapi.o_void:
                result.append( Operand(i, self.iea) )

        return result


    def __get_insn_t(self):
        """Internal. Don't use.
        Queries IDA for getting the inst_t object representing an instruction.
        Unfortunately, this structure is not persistent. Thus, it has to be
        queried for each usage.
        @return: inst_t object for the current instruction.
        """
        ins = idautils.DecodeInstruction(self.iea)
        if ins:
            return ins
        return None

    def __repr__(self):        
        return idaapi.tag_remove( idaapi.generate_disasm_line(self.iea) )



################################ operand object ##########################

class Operand(object):
    """This object represents an operand in IDA. Use it for convenience
    like the function object"""

    def __init__(self, oper_num, inst_ea):
        """Initialize the instruction object.
        @param oper_num: Number of the operand in IDA
        @type oper_num: int (ea)
        @param inst_ea: Address of the instruction of the operand
        @type inst_ea: int (ea)
        """
        self.onum = oper_num
        self.iea = inst_ea


    def get_immediate(self):
        """Get the immediate value of this operand. (Immediate=constant).
        @return: Constant/immediate value
        """
        oper = self.__get_op_t()
        if not oper or oper.type != idaapi.o_imm:
            return None        
        value = oper.value
        # make sure, its not a reference but really constant
        if value in idautils.DataRefsFrom(self.iea):
            return None

        return value


    def get_string(self):
        """Returns the string referenced by this operand.
        @return: String represented by operand or C{None} if no string.
        """
        mem = self.get_memory_address()
        if not mem:
            return None

        flags = idaapi.getFlags(mem)
        if not idaapi.isASCII(flags):
            return None

        tinfo = idaapi.opinfo_t()
        idaapi.get_opinfo(mem, 0, flags, tinfo)
        slen = idaapi.get_max_ascii_length(mem, tinfo.strtype)
        return idaapi.get_ascii_contents(mem, slen, tinfo.strtype)


    def get_memory_address(self):
        """Get the memory address used by the operand.
        @return: Memory address or C{None} if operand doesn't reference memory
        """
        oper = self.__get_op_t()
        if oper.type == idaapi.o_mem:
            return oper.addr
        elif oper.type == idaapi.o_imm and self.iea != BADADDR:
            ref = oper.value
            if ref in idautils.DataRefsFrom(self.iea):
                return ref
        elif (oper.type == idaapi.o_displ or oper.type == idaapi.o_phrase) \
             and not self.is_stackref():
            return oper.addr

        return None


    def is_stackref(self):
        """Checks if the current operand references a stack object.
        @return: C{True} if stack varable is referenced. C{False} otherwise.
        """
        oper = self.__get_op_t()
        if not oper.type in [idaapi.o_displ, idaapi.o_phrase]:
            return False

        offset = u2signed(oper.addr)
        return ( idaapi.get_stkvar(oper, offset) != None )


    def __get_op_t(self):
        """Internal. Don't use
        Queries IDA for getting the op_t structure representing an operand.
        Unfortunately, this structure is not persistent. Thus, it has to be
        queried for each usage.
        @return: op_t object for the considered operand
        """
        ins = idautils.DecodeInstruction(self.iea)

        if not ins:
            return None
        else:
            return ins.Operands[self.onum]



#====================================================================
#                       M A I N
#====================================================================



if __name__ == "__main__":
    #wingdbstub.Ensure()
    start = time.time()
    IDATA_SEGMENTS = get_import_segments()
    #cProfile.run('re_source(SEARCH_ALL_FUNCTIONS)')   # profile to work on performance 
    re_source(SEARCH_ALL_FUNCTIONS)
    end = time.time()
    thetime = end - start
    print "run-time: " + str(thetime) + " s"
