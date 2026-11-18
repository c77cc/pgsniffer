package main

import (
	"fmt"

	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
)

const captureFilterSnapshotLength = 65536

type filterInstruction struct {
	instruction bpf.Instruction
	trueLabel   string
	falseLabel  string
}

type filterBuilder struct {
	instructions []filterInstruction
	labels       map[string]int
}

func newFilterBuilder() *filterBuilder { return &filterBuilder{labels: make(map[string]int)} }

func (b *filterBuilder) label(name string) { b.labels[name] = len(b.instructions) }

func (b *filterBuilder) add(instruction bpf.Instruction) {
	b.instructions = append(b.instructions, filterInstruction{instruction: instruction})
}

func (b *filterBuilder) jumpIf(value uint32, trueLabel, falseLabel string) {
	b.instructions = append(b.instructions, filterInstruction{
		instruction: bpf.JumpIf{Cond: bpf.JumpEqual, Val: value}, trueLabel: trueLabel, falseLabel: falseLabel,
	})
}

func (b *filterBuilder) jumpIfBitsSet(mask uint32, trueLabel, falseLabel string) {
	b.instructions = append(b.instructions, filterInstruction{
		instruction: bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: mask}, trueLabel: trueLabel, falseLabel: falseLabel,
	})
}

func (b *filterBuilder) assemble() ([]bpf.RawInstruction, error) {
	instructions := make([]bpf.Instruction, len(b.instructions))
	for index, symbolic := range b.instructions {
		switch instruction := symbolic.instruction.(type) {
		case bpf.JumpIf:
			trueSkip, err := b.skip(index, symbolic.trueLabel, 255)
			if err != nil {
				return nil, err
			}
			falseSkip, err := b.skip(index, symbolic.falseLabel, 255)
			if err != nil {
				return nil, err
			}
			instruction.SkipTrue, instruction.SkipFalse = uint8(trueSkip), uint8(falseSkip)
			instructions[index] = instruction
		default:
			instructions[index] = symbolic.instruction
		}
	}
	return bpf.Assemble(instructions)
}

func (b *filterBuilder) skip(index int, label string, maximum int) (int, error) {
	target, ok := b.labels[label]
	if !ok {
		return 0, fmt.Errorf("unknown BPF label %q", label)
	}
	skip := target - index - 1
	if skip < 0 || skip > maximum {
		return 0, fmt.Errorf("invalid BPF jump from %d to %d", index, target)
	}
	return skip, nil
}

func serverPortFilter(port uint16) ([]bpf.RawInstruction, error) {
	builder := newFilterBuilder()
	builder.add(bpf.LoadAbsolute{Off: 12, Size: 2})
	builder.jumpIf(uint32(layers.EthernetTypeIPv4), "ipv4", "check_ipv6")
	builder.label("check_ipv6")
	builder.jumpIf(uint32(layers.EthernetTypeIPv6), "ipv6", "check_vlan_1_dot1q")
	builder.label("check_vlan_1_dot1q")
	builder.jumpIf(uint32(layers.EthernetTypeDot1Q), "vlan_1", "check_vlan_1_qinq")
	builder.label("check_vlan_1_qinq")
	builder.jumpIf(uint32(layers.EthernetTypeQinQ), "vlan_1", "drop")

	addIPv4PortFilter(builder, "ipv4", 14, port)
	addIPv6PortFilter(builder, "ipv6", 14, port)

	builder.label("vlan_1")
	builder.add(bpf.LoadAbsolute{Off: 16, Size: 2})
	builder.jumpIf(uint32(layers.EthernetTypeIPv4), "vlan_1_ipv4", "vlan_1_check_ipv6")
	builder.label("vlan_1_check_ipv6")
	builder.jumpIf(uint32(layers.EthernetTypeIPv6), "vlan_1_ipv6", "check_vlan_2_dot1q")
	builder.label("check_vlan_2_dot1q")
	builder.jumpIf(uint32(layers.EthernetTypeDot1Q), "vlan_2", "check_vlan_2_qinq")
	builder.label("check_vlan_2_qinq")
	builder.jumpIf(uint32(layers.EthernetTypeQinQ), "vlan_2", "drop")
	addIPv4PortFilter(builder, "vlan_1_ipv4", 18, port)
	addIPv6PortFilter(builder, "vlan_1_ipv6", 18, port)

	builder.label("vlan_2")
	builder.add(bpf.LoadAbsolute{Off: 20, Size: 2})
	builder.jumpIf(uint32(layers.EthernetTypeIPv4), "vlan_2_ipv4", "vlan_2_check_ipv6")
	builder.label("vlan_2_check_ipv6")
	builder.jumpIf(uint32(layers.EthernetTypeIPv6), "vlan_2_ipv6", "drop")
	addIPv4PortFilter(builder, "vlan_2_ipv4", 22, port)
	addIPv6PortFilter(builder, "vlan_2_ipv6", 22, port)

	builder.label("accept")
	builder.add(bpf.RetConstant{Val: captureFilterSnapshotLength})
	builder.label("drop")
	builder.add(bpf.RetConstant{Val: 0})
	return builder.assemble()
}

func addIPv4PortFilter(builder *filterBuilder, label string, networkOffset uint32, port uint16) {
	builder.label(label)
	builder.add(bpf.LoadAbsolute{Off: networkOffset + 9, Size: 1})
	builder.jumpIf(uint32(layers.IPProtocolTCP), label+"_fragments", "drop")
	builder.label(label + "_fragments")
	builder.add(bpf.LoadAbsolute{Off: networkOffset + 6, Size: 2})
	builder.jumpIfBitsSet(0x3fff, "accept", label+"_ports")
	builder.label(label + "_ports")
	builder.add(bpf.LoadMemShift{Off: networkOffset})
	builder.add(bpf.LoadIndirect{Off: networkOffset, Size: 2})
	builder.jumpIf(uint32(port), "accept", label+"_destination")
	builder.label(label + "_destination")
	builder.add(bpf.LoadIndirect{Off: networkOffset + 2, Size: 2})
	builder.jumpIf(uint32(port), "accept", "drop")
}

func addIPv6PortFilter(builder *filterBuilder, label string, networkOffset uint32, port uint16) {
	builder.label(label)
	builder.add(bpf.LoadAbsolute{Off: networkOffset + 6, Size: 1})
	// Extension headers make the TCP offset variable. Let those packets reach
	// the protocol decoder and apply the exact endpoint filter in user space.
	builder.jumpIf(uint32(layers.IPProtocolTCP), label+"_source", "accept")
	builder.label(label + "_source")
	builder.add(bpf.LoadAbsolute{Off: networkOffset + 40, Size: 2})
	builder.jumpIf(uint32(port), "accept", label+"_destination")
	builder.label(label + "_destination")
	builder.add(bpf.LoadAbsolute{Off: networkOffset + 42, Size: 2})
	builder.jumpIf(uint32(port), "accept", "drop")
}
