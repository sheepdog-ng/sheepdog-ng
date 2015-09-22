# Copyright (C) 2015 China Mobile Inc.
#
# zhangsong <zhangsong@cmss.chinamobile.com>
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License version
#2 as published by the Free Software Foundation.
#
#You should have received a copy of the GNU General Public License
#along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""
A python wrapper of sheepdog client c library libsheepdog.so .
"""

from ctypes import *

errlist = [
    "Success", #errcode : 0
    "Unknown error", #errcode : 1
    "No object found", #errcode : 2
    "I/O error", #errcode : 3
    "VDI exists already", #errcode : 4
    "Invalid parameters", #errcode : 5
    "System error", #errcode : 6
    "VDI is already locked", #errcode : 7
    "No VDI found", #errcode : 8
    "No base VDI found", #errcode : 9
    "Failed to read from requested VDI", #errcode : 10
    "Failed to write to requested VDI", #errcode : 11
    "Failed to read from base VDI", #errcode : 12
    "Failed to write to base VDI", #errcode : 13
    "Failed to find requested tag", #errcode : 14
    "System is still booting", #errcode : 15
    "VDI is not locked", #errcode : 16
    "System is shutting down", #errcode : 17
    "Out of memory on server", #errcode : 18
    "Maximum number of VDIs reached", #errcode : 19
    "Protocol version mismatch", #errcode : 20
    "Server has no space for new objects", #errcode : 21
    "Waiting for cluster to be formatted", #errcode : 22
    "Waiting for other nodes to join cluster", #errcode : 23
    "Node has failed to join cluster", #errcode : 24
    "IO has halted as there are not enough living nodes", #errcode : 25
    "Object is read-only", #errcode : 26
    "reserved", #errcode : 27
    "reserved", #errcode : 28
    "Inode object is invalidated" #errcode : 29
]

class SheepdogException(Exception):
    pass

def err_handle(errcode):
    if (not ( 0<=errcode and errcode<len(errlist) ) ) or errlist[errcode]== 'reserved':
        raise SheepdogException('Unexpected error.')
    else:
        raise SheepdogException(errlist[errcode])


libshared = cdll.LoadLibrary("libsheepdog.so")

sd_connect = libshared.sd_connect
sd_connect.argtypes = [c_char_p]
sd_connect.restype = c_void_p

sd_disconnect = libshared.sd_disconnect
sd_disconnect.argtypes = [c_void_p]
sd_disconnect.restype = c_int

sd_vdi_create = libshared.sd_vdi_create
sd_vdi_create.argtypes = [c_void_p, c_char_p, c_ulonglong]
sd_vdi_create.restype = c_int

sd_vdi_delete = libshared.sd_vdi_delete
sd_vdi_delete.argtypes = [c_void_p, c_char_p, c_char_p]
sd_vdi_delete.restype = c_int

sd_vdi_open = libshared.sd_vdi_open
sd_vdi_open.argtypes = [c_void_p, c_char_p, c_char_p]
sd_vdi_open.restype = c_void_p

sd_vdi_close = libshared.sd_vdi_close
sd_vdi_close.argtypes = [c_void_p]
sd_vdi_close.restype = c_int

sd_vdi_read = libshared.sd_vdi_read
sd_vdi_read.argtypes = [c_void_p, c_void_p, c_ulonglong, c_ulonglong]
sd_vdi_read.restype = c_int

sd_vdi_write = libshared.sd_vdi_write
sd_vdi_write.argtypes = [c_void_p, c_void_p, c_ulonglong, c_ulonglong]
sd_vdi_write.restype = c_int

sd_vdi_snapshot = libshared.sd_vdi_snapshot
sd_vdi_snapshot.argtypes = [c_void_p, c_char_p, c_char_p]
sd_vdi_snapshot.restype = c_int

sd_vdi_clone = libshared.sd_vdi_clone
sd_vdi_clone.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
sd_vdi_clone.restype = c_int

class sheepdog_driver():
    '''the sheepdog driver class.
    @connection: a connection to the sheepdog server.
    :each method of the class may raise a SheepdogException.
    '''
    def __init__(self, connection):
        self.connection = connection

    '''Disconnect to the sheepdog cluster.'''
    def disconnect(self):
        err_code = sd_disconnect(self.connection)
        if err_code != 0:
            err_handle(err_code)

    '''Create a logic volume in the sheepdog cluster.
    @name: the name of the volume to be created.
    @size: the size(Byte) of the volume to be created.
    '''
    def create(self, name, size):
        err_code = sd_vdi_create(self.connection, name, size)
        if err_code != 0:
            err_handle(err_code)

    '''Delete a logic volume in the sheepdog cluster.
    @name: the name of the volume to be deleted
    @tag: the snapshot tag of the volume, to delete a volume(not a snapshot), set tag to NULL. A volume
        can have many snapshots, the tag is used to identify the different snapshot.
    '''
    def delete(self, name, tag):
        err_code = sd_vdi_delete(self.connection, name, tag)
        if err_code != 0:
            err_handle(err_code)

    '''Open the named volume.
    @name: the name of the volume to be opened.
    @tag: snapshot tag of the volume to be opened, if the volume is not snapshot, set tag to NULL.
    :returns: the volume descritor.
    '''
    def open(self, name, tag):
        vd = sd_vdi_open(self.connection, name, tag)
        if vd ==None:
            raise SheepdogException('open specified volume name:%s tag:%s error.'%(name,tag))
        return vd

    '''Close a volume that the volume descritor point to.
    @vd: the volume descritor.
    '''
    def close(self, vd):
        err_code = sd_vdi_close(vd)
        if err_code != 0:
            err_handle(err_code)

    '''Read from a volume at a given offset.
    @vd: the volume descritor.
    @size: how many bytes we want to read.
    @offset: the start of the volume we try to read.
    :returns: the read data.
    '''
    def read(self, vd, size, offset):
        buffer = create_string_buffer(size)
        err_code = sd_vdi_read(vd, buffer, size, offset)
        if err_code != 0:
            err_handle(err_code)
        return buffer.raw

    '''Write data to a volume at a given offset.
    @vd: the volume descritor.
    @size: how many bytes we want to write.
    @offset: the start of the volume we try to write.
    @data: the data to be write.
    '''
    def write(self, vd, data, size, offset):
        err_code = sd_vdi_write(vd, data, size, offset)
        if err_code != 0:
            err_handle(err_code)

    '''Take a snapshot of a volume.
    @name: the name of the volume to snapshot
    @tag: specify a tag of the snapshot
    '''
    def snapshot(self, name, tag):
        err_code = sd_vdi_snapshot(self.connection, name, tag)
        if err_code != 0:
            err_handle(err_code)

    ''' Clone a new volume from a snapshot.
    @srcname: the source volume name.
    @srctag: the source tag of the snapshot.
    @dstname: the destination volume name.

    :Only snapshot can be cloned.
    '''
    def clone(self, srcname, srctag, dstname):
        err_code = sd_vdi_clone(self.connection, srcname, srctag, dstname)
        if err_code != 0:
            err_handle(err_code)

'''Connect to the Sheepdog cluster.
@server_host: the sheepdog server, a combination of ip and port , default value is '127.0.0.1:7000'.
:returns: an object of sheepdog_driver.
:a SheepdogException will be raised if connect error.
'''
def connect(server_host='127.0.0.1:7000'):
    connection = sd_connect(server_host)
    if connection == None:
        raise SheepdogException('connect to sheepdog server %s error.'%server_host)
    return sheepdog_driver(connection)
