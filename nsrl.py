import argparse
import struct
import math
from os.path import join
import os
from heapq import merge
import csv

MD5_SIZE = 16
SHA1_SIZE = 20

class SoftwareReference():

    def __init__(self,entry):
        row = csv.reader([entry.decode('utf-8')]).__next__()
        #print(row)
        self.sha1 = row[0]
        self.md5 = row[1]
        self.crc32 = row[2]
        self.filename = row[3]
        self.filesize = int(row[4])
        self.productCode = int(row[5])
        self.opSystemCode = row[6]
        self.specialCode = row[7]
        self.productName = None
        self.productVersion = None
        self.mfgCode = None
        self.language = None
        self.applicationType = None

    def populateProduct(self,nsrlProd):
        for p in nsrlProd[1:]:
            if int(p[0])==self.productCode: # and p[3]==self.opSystemCode:
                self.productName = p[1]
                self.productVersion = p[2]
                self.mfgCode = p[4]
                self.language = p[5]
                self.applicationType = p[6]
                return

    def __str__(self):
        fmtstring = """SoftwareReferece [
\t                SHA-1 = {self.sha1}
\t                  MD5 = {self.md5}
\t                CRC32 = {self.crc32}
\t             Filename = {self.filename}
\t            File Size = {self.filesize!s}
\t         Product Code = {self.productCode!s}
\tOperating System Code = {self.opSystemCode}
\t         Special Code = {self.specialCode}
\tPRODUCT INFO:
\t         Product Name = {self.productName}
\t      Product Version = {self.productVersion}
\t             Mfg Code = {self.mfgCode}
\t             Language = {self.language}
\t     Application Type = {self.applicationType}
]"""
        return fmtstring.format(self=self)

def createNsrlProd(nsrl):
    NSRLProd = join(nsrl,'NSRLProd.txt')
    nsrlProd = []
    with open(NSRLProd) as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            nsrlProd.append(row)
    #print(str(len(nsrlProd)))
    return nsrlProd
        
def initializeIndex(nsrlUnifiedPath):
    NSRLFile = join(nsrlUnifiedPath,'NSRLFile.txt')
    indexes = dict()
    indexes['sha1'] = dict(name='sha1',rawpath=join(nsrlUnifiedPath,'sha1raw.index'),size=SHA1_SIZE,chunk_files=[])
    indexes['md5'] = dict(name='md5',rawpath=join(nsrlUnifiedPath,'md5raw.index'),size=MD5_SIZE,chunk_files=[])
    pos = 0
    lines = 0
    file_cleanup = []
    with open(NSRLFile,'rb') as h, open(indexes['sha1']['rawpath'],'wb') as sha1_file, open(indexes['md5']['rawpath'],'wb') as md5_file:
        pos = len(h.readline()) # discard header
        line = h.readline()
        while line:
            record = line.decode('ascii',errors='replace').split(',',maxsplit=2)
            sha1 = bytes.fromhex(record[0].strip('"'))
            md5 = bytes.fromhex(record[1].strip('"'))
            p = struct.pack('q',pos) # convert position to binary representation of length 8 bytes
            sha1_file.write(sha1+p)
            md5_file.write(md5+p)
            pos += len(line)
            line = h.readline()
            lines+=1
    print("Processed {:d} records".format(lines))
    print("Performing sort...")
    for name in indexes:
        print("Creating sorted chunks for " + name + "...")
        index = indexes[name]
        hash_size = index['size']
        record_size = hash_size + 8
        chunk = int(math.pow(10,7))
        chunk_count = 0
        chunk_files = index['chunk_files']
        with open(index['rawpath'],'rb') as fin:
            data = fin.read(chunk*record_size)
            while data:
                hashes = [(data[i:i+hash_size],data[i+hash_size:i+record_size]) for i in range(0,len(data),record_size)] # convert record to tuple of (hash,position)
                hashes.sort()
                cfile = join(nsrlUnifiedPath,name+str(chunk_count)+'.chunk')
                chunk_files.append(cfile) # append this sorted chunk to the list of files to merge later
                print("Writing sorted chunk to " + cfile)
                with open(cfile,'wb') as fout:
                    for h in hashes:
                        fout.write(h[0])
                        fout.write(h[1])
                chunk_count+=1
                data = fin.read(chunk*record_size)
        file_cleanup.append(index['rawpath'])
    print("Performing merge...")
    for name in indexes:
        print("Merging sorted chunks for " + name + "...")
        index = indexes[name]
        hash_size = index['size']
        chunk_files = index['chunk_files']
        record_size = hash_size + 8
        merge_count = 0
        handles = [open(f,'rb') for f in chunk_files]
        file_cleanup = file_cleanup + chunk_files
        while len(handles) > 1:
            f = merge_files(handles[0], handles[1], join(nsrlUnifiedPath,name), merge_count, record_size, hash_size)
            handles = handles[2:] + [open(f,'rb')]
            file_cleanup.append(f)
            merge_count+=1
        handles[0].close()
        if f is not None:
            file_cleanup.remove(f)
            os.rename(f,join(nsrlUnifiedPath,name+'.index'))
    for f in file_cleanup:
        print("Deleting " + f + "...")
        # os.remove(f)
    
def read_hash_chunk(fin,chunk_size,hash_size):
    chunk = fin.read(chunk_size)
    while chunk:
        yield (chunk[0:hash_size],chunk[hash_size:])
        chunk = fin.read(chunk_size)

def merge_files(h1,h2,prefix,count,record_size,hash_size):
    merged_file = prefix+str(count)+'.merged'
    with open(merged_file,'wb') as mfile:
        c1 = h1.read(record_size)
        c2 = h2.read(record_size)
        while c1 and c2:
            if c1[:hash_size] < c2[:hash_size]:
                mfile.write(c1)
                c1 = h1.read(record_size)
            else:
                mfile.write(c2)
                c2 = h2.read(record_size)
        if c1:
            mfile.write(h1.read())
        elif c2:
            mfile.write(h2.read())
        h1.close()
        h2.close()
    return merged_file

def fetch(values,nsrl):
    values = [(struct.unpack('q',v[len(v)-8:])[0],v[:len(v)-8]) for v in values if v is not None]
    sorted(values)
    NSRLFile = join(nsrl,'NSRLFile.txt')
    nsrlProd = createNsrlProd(nsrl)
    with open(NSRLFile,'rb') as f:    
        for v in values:
            print("Fetching value for " + v[1].hex())
            f.seek(v[0])
            sr = SoftwareReference(f.readline())
            sr.populateProduct(nsrlProd)
            print(sr)
            #print(f.readline())

def binary_search(nsrlPath, hash):
    hash = bytes.fromhex(hash)
    name = 'sha1' if len(hash)==SHA1_SIZE else 'md5'
    hash_size = len(hash)
    record_size = hash_size+8
    index_path = join(nsrlPath,name+'.index')
    upper = int(os.stat(index_path).st_size / record_size)
    with open(index_path,'rb') as index:
        middle = int(upper/2)
        while middle != upper:
            #print("upper= {:d}, middle = {:d}".format(upper,middle))
            index.seek(middle*record_size)
            v = index.read(record_size)
            if v[:hash_size]==hash:
                return v
            elif v[:hash_size]<hash:
                middle = int((upper+middle+1)/2)
            else:
                upper = middle
                middle = 0 if upper == 0 else int(upper/2)
    print("{} not found.".format(hash.hex()))

def search(nsrlPath,hash):
    hash = bytes.fromhex(hash)
    name = 'sha1' if len(hash)==SHA1_SIZE else 'md5'
    hash_size = len(hash)
    record_size = hash_size+8
    index_path = join(nsrlPath,name+'.index')
    upper = int(os.stat(index_path).st_size / record_size)
    with open(index_path,'rb') as index:
        middle = int(upper/2)
        while middle != upper:
            #print("upper= {:d}, middle = {:d}".format(upper,middle))
            index.seek(middle*record_size)
            v = index.read(record_size)
            if v[:hash_size]==hash:
                step = 2
                while v[:hash_size]==hash and middle != 0:
                    middle = 0 if middle < step else middle-step
                    step = step*step
                    index.seek(middle*record_size)
                    v = index.read(record_size)
                while v[:hash_size]!=hash:
                    v = index.read(record_size)
                matches = []
                while v[:hash_size]==hash:
                    matches.append(v)
                    v = index.read(record_size)
                return matches
            elif v[:hash_size]<hash:
                middle = int((upper+middle+1)/2)
            else:
                upper = middle
                middle = 0 if upper == 0 else int(upper/2)
    print("{} not found.".format(hash.hex()))
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A tool for working with NSRL hashsets')
    parser.add_argument('command',help='the action to perform, such as "init" or "query"')
    parser.add_argument('-n','--nsrl',help='the path to the NSRL dataset',required=True)
    parser.add_argument('--hash',help='the hash to search in hex',required=False)
    parser.add_argument('--hashfile',help='a file produced by hashdeep',required=False)
    args = parser.parse_args()
    if args.command=='init':
        print('init')
        initializeIndex(args.nsrl)
    if args.command=='sort':
        print("Performing sort...")
        size = 20+4+8
        chunk = int(math.pow(10,7))
        count = 0
        with open('sha1.txt','rb') as fin:
            data = fin.read(chunk*size)
            while data:
                hashes = [(data[i:i+20],data[i+20:i+size]) for i in range(0,len(data),size)]
                hashes.sort()
                with open('sha1.'+str(count)+'.index','wb') as fout:
                    for h in hashes:
                        fout.write(h[0])
                        fout.write(h[1])
                count+=1
                data = fin.read(chunk*size)
        md5Size = 16+4+8
    if args.command=='merge':
        print("Performing merge...")
        count = 0
        size = 20+4+8
        handles = [open(f,'rb') for f in os.listdir() if '.index' in f]
        while len(handles) > 1:
            h = merge_files(handles[0],handles[1],count,size,20)
            handles = handles[2:]+[h]
            count+=1
        handles[0].close()
    if args.command=='search':
        print("Performing search...")
        if not args.hash:
            if not args.hashfile:
                print("Hash or hashfile is required for this command")
            else:
                with open(args.hashfile) as hfile:
                    fetch([binary_search(args.nsrl,hash.strip('\r\n')) for hash in hfile.readlines()],args.nsrl)
        else:
            result = search(args.nsrl,args.hash)
            if result:
                fetch(result,args.nsrl)