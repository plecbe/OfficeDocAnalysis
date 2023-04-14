"""
----LICENSE----
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>

"""
__module__  = "MyOleFileParser.py"
__date__    = "2023-03-10"
__version__ = "X0.0"
__author__  = "P.Leclercq"

import struct
import argparse

# Some constants
MAGICOLESIG = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'   # OLE file signature
NUMBER_DIFAT_ENTRIES_IN_HEADER = 109                # Number of DIFAT entries in header 
DIFATSECTOR = 0xFFFFFFFC                            # DIFAT sector
FATSECTOR = 0xFFFFFFFD                              # FAT sector
ENDOFCHAIN = 0xFFFFFFFE                             # End of chain value
UNALLOCATED = 0xFFFFFFFF                            # Unallocated entry

# Parse CLSID
# CLSID is a mixed endian array
# Address:  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
# Order:    03 02 01 00 05 04 07 06 08 09 0A 0B 0C 0D 0E 0F
def parse_clsid(P_clsid):
    clsid2=""
    for i in range(4):
        clsid2 += "{0:02X}".format(P_clsid[3-i])
    clsid2 += "-"
    for i in range(5, 3, -1):
        clsid2 += "{0:02X}".format(P_clsid[i])
    clsid2 += "-"
    for i in range(7, 5, -1):
        clsid2 += "{0:02X}".format(P_clsid[i])
    clsid2 += "-"
    for i in range(8,10):
        clsid2 += "{0:02X}".format(P_clsid[i])
    clsid2 += "-"
    for i in range(10,16):
        clsid2 += "{0:02X}".format(P_clsid[i])
    return(clsid2)
    
    
# Parse directory entries (recursively)
# The directory entries are organized in a tree
# Each entry can have a left and a right sibling
# and storages can have a child
#                   +----------------------+
#                   | dir entry2 (storage) |
#  dir entry 1 <--- | left sibling         |
#                   | right sibling        |----> dir entry 3
#                   | child --+            |
#                   +---------|------------+
#                             V
#                       dir entry 4
# We will recursively traverse the tree, starting with each left sibling until end of chain
# then dumping the current entry, then the right sibling, then the potential child
#

def dump_entry(P_DirEntries, P_Index, P_Indent = 0):
    # Parse directory entry
    DirEntry = P_DirEntries[P_Index]
    myOffset = DirEntry["offset"]
    directory_entry_name = DirEntry["data"][0:64]
    directory_entry_name_length = struct.unpack_from('<H', DirEntry["data"],64)[0]
    object_type = struct.unpack_from('<c', DirEntry["data"],66)[0]
    color_flag = struct.unpack_from('<c', DirEntry["data"],67)[0]
    left_sibling = struct.unpack_from('<I', DirEntry["data"],68)[0]
    right_sibling = struct.unpack_from('<I', DirEntry["data"],72)[0]
    child_id  = struct.unpack_from('<I', DirEntry["data"],76)[0]
    clsid = DirEntry["data"][80:96]
    state_bits = struct.unpack_from('<I', DirEntry["data"],96)[0]
    creation_time = struct.unpack_from('<Q', DirEntry["data"],100)[0]
    modified_time = struct.unpack_from('<Q', DirEntry["data"],108)[0]
    starting_sector_location = struct.unpack_from('<I', DirEntry["data"],116)[0]
    stream_size = struct.unpack_from('<Q', DirEntry["data"],120)[0]
    
    # Add attributes
    P_DirEntries[P_Index]["start"] = starting_sector_location
    P_DirEntries[P_Index]["type"] = object_type
    P_DirEntries[P_Index]["id"] = P_Index
    P_DirEntries[P_Index]["size"] = stream_size

    # If left sibling exists, dump it
    if left_sibling != UNALLOCATED:
        dump_entry(P_DirEntries, left_sibling, P_Indent)

    # Print directory entry - UTF16 but can contain non printable chars
    print("0x{0:>08X} ".format(myOffset), end="|")
    print("{0:>3d} ".format(P_Index), end="|")
    myDirname = directory_entry_name.decode("utf-16le").rstrip("\x00")
    myDirname = P_Indent * "  " + myDirname
    myLen = 0
    for i in range(len(myDirname)):
        if myDirname[i].isprintable():
            print(myDirname[i], end="")
            myLen += 1
        else:
            print("x\{0:02X}".format(ord(myDirname[i])), end="")
            myLen += 4
    for i in range(32 - myLen):
        print(" ", end="")
    print("|", end="")  
    if object_type == b'\x00':
        print(" Unalloc ", end="|")
    elif object_type == b'\x01':        
        print(" Storage ", end="|")
    elif object_type == b'\x02':
        print(" Stream  ", end="|")
    elif object_type == b'\x05':
        print(" Root    ", end="|")        
    else:
        print(" Unknown ", end="|")
    print(" 0x{0:08X} ".format(stream_size), end="|")
    print(" 0x{0:>8X} ".format(starting_sector_location), end="|")
    print(" 0x{0:>8X} ".format(child_id), end="|")   
    print(" 0x{0:>8X} ".format(left_sibling), end="|")
    print(" 0x{0:>8X} ".format(right_sibling), end="|")
    clsid2 = parse_clsid(clsid)
    if clsid2 != "00000000-0000-0000-0000-000000000000":
        print(clsid2)
    else:
        print()
    
    # If right sibling exists, dump it
    if right_sibling != UNALLOCATED:
        dump_entry(P_DirEntries, right_sibling, P_Indent)
    # If it is a storage entry, dump child - start with root storage    
    if object_type == b'\x05' and child_id != 0:
        dump_entry(P_DirEntries, child_id, P_Indent)
    else:
        if object_type == b'\x01' and child_id != 0:
            dump_entry(P_DirEntries, child_id, P_Indent + 1)
    return(P_DirEntries)

# Main program
def main():
    # Parse OLE filename   
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="OLE file to be parsed")
    args = parser.parse_args()
    P_filename = args.filename
    print ("Filename: ",P_filename)
    
    # Open the OLE file in binary mode
    with open(P_filename, 'rb') as f:
        # Check we find the magic number in the first 8 bytes
        magic = f.read(8)
        if magic != MAGICOLESIG:
            print("!!!! Not an OLE file !!!!")
            f.close()
            exit(1)
        # Read the header information from the file    
        clsid = f.read(16)
        minor_version = struct.unpack('<H', f.read(2))[0]
        major_version = struct.unpack('<H', f.read(2))[0]
        byte_order = struct.unpack('<H', f.read(2))[0]
        sector_shift = struct.unpack('<H', f.read(2))[0]
        mini_sector_shift = struct.unpack('<H', f.read(2))[0]
        reserved = f.read(6)
        directory_sector_count = struct.unpack('<I', f.read(4))[0]
        fat_sector_count = struct.unpack('<I', f.read(4))[0]
        first_directory_sector_id = struct.unpack('<I', f.read(4))[0]
        transaction_signature_number = struct.unpack('<I', f.read(4))[0]
        mini_stream_cutoff_size = struct.unpack('<I', f.read(4))[0]
        first_mini_fat_sector_id = struct.unpack('<I', f.read(4))[0]
        mini_fat_sector_count = struct.unpack('<I', f.read(4))[0]
        first_difat_sector_id = struct.unpack('<I', f.read(4))[0]
        difat_sector_count = struct.unpack('<I', f.read(4))[0]
        difat_entries = []
        # Read the 109 DIFAT entries in the header
        for i in range(NUMBER_DIFAT_ENTRIES_IN_HEADER):
            difat_entries.append(struct.unpack('<I', f.read(4))[0])   

        # Compute sector size
        mySectorSize = 2 ** sector_shift

        # Print the header information
        print("======== CBF header - size: " + str(mySectorSize) + " bytes ========")
        print("  Field                     | Offset | Size |    Expected                   | Value")
        print("Magic number                |    0x0 |    8 | 0xD0 CF 11 E0 A1 B1 1A E1     | ", end="")
        for i in range(8):
            print("0x{0:X} ".format(magic[i]), end="")
        print()           
        print("CLSID                       |    0x8 |   16 | all 0s                        | ", end="")
        for i in range (16):    
            print ("{0:02X}".format(clsid[i]), end="")
        print("")           
        print("Version                     |   0x18 |    4 | 3.62 or 4.62                  | {0:d}.".format(major_version) + "{0:d}".format(minor_version))
        print("Byte Order                  |   0x1C |    2 | 0xFFFE                        | 0x{0:X}".format(byte_order))
        if major_version == 3:
            print("Sector Shift                |   0x1E |    2 | 0x0009 -> sector size=2^9=512 bytes: {0:d}".format(sector_shift))
        else:
            print("Sector Shift                |   0x1E |    2 | 0x000C -> sector size=2^12=4096 bytes: {0:d}".format(sector_shift))
        print("Mini Sector Shift           |   0x20 |    2 | 0x0006 -> mini stream sector size=2^6=64 bytes): {0:d}".format(mini_sector_shift))
        print("Reserved                    |   0x22 |    6 | all 0s                        | ", end="")
        for i in range(6):
            print("0x{0:X} ".format(reserved[i]), end="")
        print()    
        print("Directory Sector Count      |   0x28 |    4 | 0 if major version is 3       | {0:d}".format(directory_sector_count))
        print("FAT Sector Count            |   0x2C |    4 |                               | {0:d}".format(fat_sector_count))
        print("First Directory Sector ID   |   0x30 |    4 |                               | {0:d} - 0x{0:X}".format(first_directory_sector_id))
        print("Transaction Signature Number|   0x34 |    4 |                               | {0:d}".format(transaction_signature_number))
        print("Mini Stream Cutoff Size     |   0x38 |    4 | 4096                          | {0:d} - 0x{0:X}".format(mini_stream_cutoff_size))
        print("First Mini FAT Sector ID    |   0x3C |    4 |                               | {0:d} - 0x{0:X}".format(first_mini_fat_sector_id))
        print("Mini FAT Sector Count       |   0x40 |    4 |                               | {0:d} - 0x{0:X}".format(mini_fat_sector_count))
        print("First DIFAT Sector ID       |   0x44 |    4 | 0xFFFFFFFE = end of chain     | {0:d} - 0x{0:X}".format(first_difat_sector_id))
        print("DIFAT Sector Count          |   0x48 |    4 |                               | {0:d} - 0x{0:X}".format(difat_sector_count))
        print("DIFAT Entries in header     |   0x4C |109 x 4 |")

        # Find last non-empty DIFAT entry
        myMaxEntry = 0
        for i in range(NUMBER_DIFAT_ENTRIES_IN_HEADER):
            if difat_entries[i] != UNALLOCATED:
                myMaxEntry = i
        # Print the allocated DIFAT entries in header
        for i in range(myMaxEntry + 1):
            print("                            |   0x{0:X} |                                      | 0x{1:X}".format(0x4C + i*4, difat_entries[i]))       
        # Build DIFAT sector chain
        print("======== DIFAT map outside header ========")
        myDifat_chain = [0]                                 # First DIFAT sector is the header
        myNextDifatSector = first_difat_sector_id           # Take next DIFAT sector number
        while myNextDifatSector != ENDOFCHAIN:
            print("Next DIFAT sector: {0:X}".format(myNextDifatSector))
            # While we are not at the end, add sector number to DIFAT chain
            myDifat_chain.append(myNextDifatSector)
            # Compute offset to next DIFAT sector
            myOffset = ((1 + myNextDifatSector) * mySectorSize)
            f.seek(myOffset, 0)
            # Append DIFAT entries to difat_entries
            for i in range((mySectorSize // 4) - 1):
                myOffset = f.tell()
                myFatSector = struct.unpack('<I', f.read(4))[0]
                difat_entries.append(myFatSector)
                print("DIFAT entry = FAT sector: offset 0x{0:X} - Value 0x{1:X}".format(myOffset, myFatSector))            
            # Last entry of the DIFAT sector is pointer to next DIFAT sector    
            myNextDifatSector = (struct.unpack('<I', f.read(4))[0])

        # Print DIFAT map
        print("DIFAT sector chain: ", end="")
        print(myDifat_chain)
     
        myAllocatedSectors = []
        # Build FAT 
        print("======== FAT map ========")
        # Loop on DIFAT entries                                   
        for i in range(len(difat_entries)):
            if difat_entries[i] == ENDOFCHAIN:
                print("DIFAT entry: " + str(i), end=" | ")
                print("End of chain - OxFFFFFFFE")
                break
            else:
                if difat_entries[i] != UNALLOCATED:  #Ignore unallocated DIFAT entries
                    print("DIFAT entry: " + str(i))
                    # Each DIFAT entry is the sector number containing FAT entries
                    print("First FAT sector: {0:d} - 0x{0:X}".format(difat_entries[i]))
                    # Compute offest to FAT sector
                    myOffset = (1 + difat_entries[i]) * mySectorSize                
                    # Build FAT map
                    f.seek(myOffset, 0)
                    # Each FAT entry is 4 bytes
                    for j in range(mySectorSize // 4):
                        # Every DIFAT entry (i) corresponds to one full sector of FAT entries.
                        # Each FAT entry is 4 bytes, so the number of FAT entries per DIFAT entry is sector
                        #  size/4.
                        # And the 0th FAT entry contains the next sector for the sector 0
                        mySectorNumber = j + (i * (mySectorSize // 4))
                        myNextSector = struct.unpack('<I', f.read(4))[0]
                        if myNextSector == FATSECTOR:
                            type = "FAT"
                        elif myNextSector == DIFATSECTOR:
                            type = "DIFAT"
                        elif myNextSector == ENDOFCHAIN:
                            type = "End of Chain"
                        elif myNextSector == UNALLOCATED:
                            type = "Free"
                        else:
                            type = "Data"
                        myAllocatedSectors.append({"number" : mySectorNumber, "next" : myNextSector, "ptroffset" : myOffset + 4*j, "type" : type, "type2" : ""})
        # Print FAT map
        print("      Sector       | Pointer offset | Sector offset | Next sector | Type")
        # Find last non-free sector
        myMaxSector = 0
        for i in range(len(myAllocatedSectors)):
            if myAllocatedSectors[i]["type"] != "Free":
                myMaxSector = i
        # Tag some sectors with their content
        # Directory sectors
        mySector = first_directory_sector_id
        while mySector != ENDOFCHAIN:
            for i in range(len(myAllocatedSectors)):
                if myAllocatedSectors[i]["number"] == mySector:
                    myAllocatedSectors[mySector]["type2"] = " - Directory"
            mySector = myAllocatedSectors[mySector]["next"]
            
        # Mini FAT sectors
        mySector = first_mini_fat_sector_id
        while mySector != ENDOFCHAIN:
            for i in range(len(myAllocatedSectors)):
                if myAllocatedSectors[i]["number"] == mySector:
                    myAllocatedSectors[mySector]["type2"] = " - Mini FAT"
            mySector = myAllocatedSectors[mySector]["next"]
            
        for i in range(myMaxSector+1):
            print(" {0:>7d} - 0x{0:>5X} |     0x{1:08X} |    0x{2:08X} |  0x{3:>8X} | {4} {5}".format(myAllocatedSectors[i]["number"], myAllocatedSectors[i]["ptroffset"], (1 + myAllocatedSectors[i]["number"]) *  mySectorSize, myAllocatedSectors[i]["next"], myAllocatedSectors[i]["type"], myAllocatedSectors[i]["type2"]))

        # Build directory sector chain
        # Start with the first directory sector number in the header
        myDirSectorChain = [first_directory_sector_id]
        myDirectorySector = first_directory_sector_id
        # Follow the FAT to find the next sectors
        while myDirectorySector != ENDOFCHAIN:
            for i in range(len(myAllocatedSectors)):
            # Find next directory sector from the FAT
                if myAllocatedSectors[i]["number"] == myDirectorySector:
                    if myAllocatedSectors[i]["type"] == "Data":
                        myDirectorySector = myAllocatedSectors[i]["next"]
                        myDirSectorChain.append(myDirectorySector)
                    elif myAllocatedSectors[i]["type"] == "End of Chain":
                        myDirectorySector = ENDOFCHAIN
                    else:
                        myDirectorySector = ENDOFCHAIN      
                        print("!!! Error in directory sector chain - unexpected sector type")
                    break    

        # Print directory sector chain
        print("======== Directory entries ========")
        print("Directory sector chain: [", end="")
        for i in range(len(myDirSectorChain)):
            print("0x{0:X} ".format(myDirSectorChain[i]), end="")
        print("]")    

        # Dump the directory entries for each directory sector
        print("=== Dump dir entries ===")
        myDirEntryList = []
        # Loop through all the directory sectors
        for i in range(len(myDirSectorChain)):
            myOffset = (myDirSectorChain[i] + 1) * mySectorSize
            f.seek(myOffset)
            # Each directory entry is 128 bytes
            for j in range(mySectorSize // 128):
                myDirEntryList.append({"data":f.read(128), "offset": myOffset + j * 128})                
        print("   Offset  | Id | Name                           |  Type   |   Size     | 1st sector | Child      | Left       |   Right    |  CLSID")
        # Dump the content of the directory entries
        dump_entry(myDirEntryList, 0, 0)                  

        # Mini sectors
        myMiniSectorSize = 2 ** mini_sector_shift
        # Get first minifat sector
        myMiniFatSectorId = first_mini_fat_sector_id
        myMiniFatEntries = []
        while myMiniFatSectorId != ENDOFCHAIN:
            # Compute offset to Mini FAT sector
            myOffset = (myMiniFatSectorId + 1) * mySectorSize
            f.seek(myOffset)
            # Each Mini FAT sector entry is 4 bytes 
            # and represents the next mini sector of the current mini sector
            for i in range(mySectorSize // 4):
                myNextMiniSector = struct.unpack('<I', f.read(4))[0]
                myMiniFatEntries.append(myNextMiniSector)
            # Find next minifat sector
            for i in range(len(myAllocatedSectors)):
                if myAllocatedSectors[i]["number"] == myMiniFatSectorId:
                    if myAllocatedSectors[i]["type"] == "Data":
                        myMiniFatSectorId = myAllocatedSectors[i]["next"]
                    elif myAllocatedSectors[i]["type"] == "End of Chain":
                        myMiniFatSectorId = ENDOFCHAIN
                    else:
                        myMiniFatSectorId = ENDOFCHAIN
                        print("!!! Error in MiniFAT sector chain - unexpected sector type")
                    break    

        print("====== Mini FAT map ======")
        print("Mini sector |   Next")
        # Find last non-free sector
        myMaxSector = 0
        for i in range(len(myMiniFatEntries)):
            if myMiniFatEntries[i] != UNALLOCATED:
                myMaxSector = i
        # Print allocated mini FAT entries
        if len(myMiniFatEntries) > 0:
            for i in range(myMaxSector + 1):
                print(" 0x{0:>8X} | 0x{1:>8X}".format(i, myMiniFatEntries[i])) 
 
        # Streams
        print("====== Streams ======")               
        # Read all streams data blocks, one mini sector at a time
        # Start with first sector of the mini stream stored in the Root Directory entry
        myMiniStreamSector = myDirEntryList[0]["start"]
        myMiniStream = []
        myMiniStreamChain = []
        while myMiniStreamSector != ENDOFCHAIN :
            # Build the sector chain for the mini streams
            myMiniStreamChain.append(myMiniStreamSector)            
            # Compute offset to sector containing mini stream
            myOffset = (myMiniStreamSector + 1) * mySectorSize        
            f.seek(myOffset)
            # Read all the mini sectors in the sector
            for i in range(mySectorSize // myMiniSectorSize):
                myMiniStream.append({"data": f.read(myMiniSectorSize), "offset": myOffset})
                myOffset += myMiniSectorSize
            # Find next data sector from FAT
            for i in range(len(myAllocatedSectors)):
                if myAllocatedSectors[i]["number"] == myMiniStreamSector:
                    if myAllocatedSectors[i]["type"] == "Data":
                        myMiniStreamSector = myAllocatedSectors[i]["next"]
                        # myMiniStreamChain.append(myMiniStreamSector)
                    elif myAllocatedSectors[i]["type"] == "End of Chain":
                        myMiniStreamSector = ENDOFCHAIN
                    else:
                        myMiniStreamSector = ENDOFCHAIN
                        print("!!! Error in Mini streams sector chain - unexpected sector type")
                    break    
        # Print streams sector chain
        print("Mini streams sector chain: [", end="")
        for i in range(len(myMiniStreamChain)):
            print("0x{0:X} ".format(myMiniStreamChain[i]), end="")
        print("]")
        # Dump the content of the data streams and mini streams
        for i in range(len(myDirEntryList)):
            # Ignore non allocated entries which were not handled by dump_entry
            if "type" in myDirEntryList[i]:
                # Only handle data streams
                if myDirEntryList[i]["type"] == b'\x02':
                    # Get starting sector number
                    myIndex = myDirEntryList[i]["start"]
                    # Get stream size
                    mySize = myDirEntryList[i]["size"]
                    print("Directory entry 0x{0:X} - size: {1} - 0x{1:X}".format(myDirEntryList[i]["id"],mySize))                
                    if mySize < mini_stream_cutoff_size:
                        # Data is in the mini streams
                        # The starting sector number is a mini sector number
                        while myIndex != ENDOFCHAIN:
                            # Dump the data bytes, 16 per line
                            for j in range(myMiniSectorSize):
                                if j % 16 == 0:
                                    print("0x{0:08X}: ".format(myMiniStream[myIndex]["offset"] + j), end="")
                                    myAsciidump =""
                                myByte = myMiniStream[myIndex]["data"][j]    
                                print("{0:02X}".format(myByte), end=" ")
                                if chr(myByte).isprintable():
                                    myAsciidump += chr(myByte)
                                else:
                                    myAsciidump += "."
                                if j % 16 == 15:
                                    print("  " + myAsciidump)                            
                            # Find the next mini sector in the mini FAT        
                            myIndex = myMiniFatEntries[myIndex]
                    else:
                        # Data is in the normal sectors
                        # The starting sector number is a 'normal' sector
                        while myIndex != ENDOFCHAIN:                   
                            f.seek((1 + myIndex) * mySectorSize)
                            myData = f.read(mySectorSize)                   
                            for j in range(mySectorSize):
                                if j % 16 == 0:
                                    print("0x{0:08X}: ".format(((1 + myIndex) * mySectorSize) + j), end="")
                                    myAsciidump =""
                                myByte = myData[j]    
                                print("{0:02X}".format(myByte), end=" ")
                                if chr(myByte).isprintable():
                                    myAsciidump += chr(myByte)
                                else:
                                    myAsciidump += "."
                                if j % 16 == 15:
                                    print("  " + myAsciidump)
                            # Find next data sector in the FAT
                            for i in range(len(myAllocatedSectors)):
                                if myAllocatedSectors[i]["number"] == myIndex:
                                    if myAllocatedSectors[i]["type"] == "Data":
                                        myIndex = myAllocatedSectors[i]["next"]
                                    elif myAllocatedSectors[i]["type"] == "End of Chain":
                                        myIndex = ENDOFCHAIN
                                    else:
                                        myIndex = ENDOFCHAIN
                                        print("!!! Error in data streams sector chain - unexpected sector type")
                                    break    
                print("---------------------------------")    
        exit(0)
#
if __name__ == "__main__":
    main()

#EOF

    
