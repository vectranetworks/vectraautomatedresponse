import abc
from abc import ABCMeta

from vectra_automated_response_consts import (
    VectraAccount,
    VectraDetection,
    VectraHost,
    VectraStaticIP,
)


class ThirdPartyInterface(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        return (
            hasattr(subclass, "block_host")
            and callable(subclass.block_host)
            and hasattr(subclass, "block_account")
            and callable(subclass.block_account)
            and hasattr(subclass, "unblock_host")
            and callable(subclass.unblock_host)
            and hasattr(subclass, "unblock_account")
            and callable(subclass.unblock_account)
            and hasattr(subclass, "groom_host")
            and callable(subclass.groom_host)
            and hasattr(subclass, "block_detection")
            and callable(subclass.block_detection)
            and hasattr(subclass, "unblock_detection")
            and callable(subclass.unblock_detection)
            and hasattr(subclass, "block_static_dst_ips")
            and callable(subclass.block_static_ds_ips)
            and hasattr(subclass, "unblock_static_dst_ips")
            and callable(subclass.unblock_static_dst_ips)
            or NotImplemented
        )

    def __init__(self):
        pass

    @abc.abstractmethod
    def block_host(self, host: VectraHost) -> list:
        """
        Block a VectraHost instance on the corresponding FW/NAC
        :rtype: list of all elements that were blocked
        """
        raise NotImplementedError

    @abc.abstractmethod
    def unblock_host(self, host: VectraHost) -> list:
        """
        Unlock a VectraHost instance on the corresponding FW/NAC
        :rtype: list of all elements that were unblocked
        """
        raise NotImplementedError

    @abc.abstractmethod
    def block_account(self, account: VectraAccount) -> list:
        """
        Block a VectraAccount instance on the corresponding system
        :rtype: list of all elements that were blocked
        """
        raise NotImplementedError

    @abc.abstractmethod
    def unblock_account(self, account: VectraAccount) -> list:
        """
        Unlock a VectraAccount instance on the corresponding system
        :rtype: list of all elements that were unblocked
        """
        raise NotImplementedError

    @abc.abstractmethod
    def groom_host(self, host: VectraHost) -> dict:
        """
        Determine if a VectraHost instance needs to be blocked or unblocked.
        :rtype: dictionary of all elements that require blocking or unblocking: {'block': [], 'unblock: []}
        """
        raise NotImplementedError

    @abc.abstractmethod
    def block_detection(self, detection: VectraDetection) -> list:
        """
        Block a VectraDetection instance on the corresponding FW/NAC
        :rtype: list of all elements that were blocked
        """
        raise NotImplementedError

    @abc.abstractmethod
    def unblock_detection(self, detection: VectraDetection) -> list:
        """
        Unblock a VectraDetection instance on the corresponding FW/NAC
        :rtype: list of all elements that were unblocked
        """
        raise NotImplementedError

    @abc.abstractmethod
    def block_static_dst_ips(self, ips: VectraStaticIP) -> list:
        """
        Block VectraStaticIP instance on the corresponding FW/NAC
        :rtype: list of IPs that were blocked
        """

    @abc.abstractmethod
    def unblock_static_dst_ips(self, ips: VectraStaticIP) -> list:
        """
        Unblock VectraStaticIP instance on the corresponding FW/NAC
        :rtype: list of IPs that were blocked
        """
