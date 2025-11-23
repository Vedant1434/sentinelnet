package com.sentinelnet.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Entity
@Table(name = "traffic_stats")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TrafficStats {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Temporal(TemporalType.TIMESTAMP)
    private Date timestamp;

    private long pps;
    private long bandwidth; // in bits per second
    private int activeFlows;
    private long tcpPackets;
    private long udpPackets;
    private long icmpPackets;
}