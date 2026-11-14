"""Small race-resistant local evidence helpers for the external supervisor."""
import os, stat
from pathlib import Path

DIR_FLAGS=os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0)
FILE_FLAGS=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)

def open_dir_nofollow(path):
    p=Path(path)
    if not p.is_absolute():
        raise ValueError('trusted directory path must be absolute')
    fd=os.open('/',DIR_FLAGS)
    try:
        for part in p.parts[1:]:
            if part in ('','.','..'): raise ValueError('invalid path component')
            nfd=os.open(part,DIR_FLAGS,dir_fd=fd); os.close(fd); fd=nfd
        return fd
    except Exception:
        os.close(fd); raise

def create_child_dir(parent,name,mode=0o700):
    if '/' in name or name in ('','.','..'): raise ValueError('invalid child name')
    os.mkdir(name,mode=mode,dir_fd=parent)
    return os.open(name,DIR_FLAGS,dir_fd=parent)

def write_exclusive(dirfd,name,data,mode=0o600):
    if '/' in name or name in ('','.','..'): raise ValueError('invalid file name')
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),mode,dir_fd=dirfd)
    try:
        with os.fdopen(fd,'wb',closefd=False) as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
    finally: os.close(fd)

def read_regular_nofollow(path):
    fd=os.open(path,FILE_FLAGS)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode): raise ValueError('not regular file')
        chunks=[]
        while True:
            b=os.read(fd,1024*1024)
            if not b: break
            chunks.append(b)
        return b''.join(chunks)
    finally: os.close(fd)
