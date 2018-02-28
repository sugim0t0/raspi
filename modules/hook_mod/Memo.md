# hook_mod開発メモ

## ethtool
NICのオフロード機能の状態確認

    $ ethtool -k eth0
TSO(TCP Segmentation-offload) ON/OFF

    $ ethtool -K eth0 tso on | off
GSO(Generic Segmentation-offload)

    $ ethtool -K eth0 gso on | off

## Netfilter
