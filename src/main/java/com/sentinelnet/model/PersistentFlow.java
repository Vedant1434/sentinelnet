package com.sentinelnet.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Entity
@Table(name = "flow_history")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PersistentFlow {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String srcIp;
    private String dstIp;
    private String protocol;
    private long packetCount;
    private long bytes;
    private int synCount;

    @Temporal(TemporalType.TIMESTAMP)
    private Date startTime;

    @Temporal(TemporalType.TIMESTAMP)
    private Date endTime;

    // Constructor for easy conversion
    public PersistentFlow(String srcIp, String dstIp, String protocol, long packetCount, long bytes, int synCount, long startTs, long endTs) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.protocol = protocol;
        this.packetCount = packetCount;
        this.bytes = bytes;
        this.synCount = synCount;
        this.startTime = new Date(startTs);
        this.endTime = new Date(endTs);
    }
}