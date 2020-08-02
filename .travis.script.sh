#!/bin/bash

set -ev

go test github.com/Kkevsterrr/gopacket
go test github.com/Kkevsterrr/gopacket/layers
go test github.com/Kkevsterrr/gopacket/tcpassembly
go test github.com/Kkevsterrr/gopacket/reassembly
go test github.com/Kkevsterrr/gopacket/pcapgo
go test github.com/Kkevsterrr/gopacket/pcap
