#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) A.Klimets 2026 under GPLv3 license
# Part of the edl client by B.Kerler
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!

import logging
import os
from edlclient.Library.utils import LogBase


class oplus(metaclass=LogBase):
    def __init__(self, fh, args=None, loglevel=logging.INFO):
        self.fh = fh
        self.args = args
        self.__logger = self.__logger
        self.__logger.setLevel(loglevel)
        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        self.warning = self.__logger.warning

    def send_signed_digest(self, filename):
        if not os.path.exists(filename):
            self.error(f"Signed digest file {filename} does not exist.")
            return False
        with open(filename, "rb") as rf:
            data = rf.read()
        self.info(f"Sending signed digest table '{filename}' ({len(data)} bytes)...")
        rsp = self.fh.xmlsend_raw(data)
        if rsp.resp:
            self.info("FIREHOSE: Signed DIGEST sent.")
            return True
        else:
            self.error("The Digitally Signed Digest Table was rejected by the target.")
            return False

    def cmd_verify(self, value="ping", enable_vip=True):
        content = f'verify value="{value}"'
        if enable_vip:
            content += ' EnableVip="1"'
        resp = self.fh.cmd_send(content)
        if resp is None:
            return False
        if isinstance(resp, bytes):
            markers = (b"verify passed", b"SHA256 output matches", b"disable vip")
            for marker in markers:
                if marker in resp:
                    self.info(f"Verify ok ({marker.decode()}), vip disabled.")
                    return True
            if b"verify failed" in resp:
                self.error("Target verify failed.")
                return False
            self.warning("Verify response not recognized, refusing to continue.")
            return False
        return True

    def cmd_sha256init(self, verbose=False):
        content = 'sha256init'
        if verbose:
            content += ' Verbose="1"'
        resp = self.fh.cmd_send(content)
        return resp is not None

    def cmd_resetdigest(self):
        resp = self.fh.cmd_send('resetdigest')
        return resp is not None

    def cmd_reset_to_edl(self):
        return self.fh.cmd_reset(mode="reset_to_edl")

    def bypass(self, digest=None, sign=None):
        if digest is None or sign is None:
            self.error("No digest/signature files given. Use --digestfile/--signfile "
                       "or modules oplus bypass,digest=<file>,sign=<file>.")
            return False
        if not self.send_signed_digest(digest):
            return False
        if not self.cmd_verify(value="ping", enable_vip=True):
            return False
        if not self.send_signed_digest(sign):
            return False
        if not self.cmd_sha256init(verbose=True):
            return False
        # clears the vip strict state left by the loaded digest table
        try:
            self.cmd_resetdigest()
        except Exception as err:  # pylint: disable=broad-except
            self.debug(f"resetdigest after bypass failed: {err}")
        self.info("Oplus bypass sequence finished, protected areas should be accessible now.")
        return True
