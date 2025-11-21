package com.sentinelnet;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PersistentAlert {
    @Id
    @GeneratedValue
    private Long id;
    private String type;
    private String description;
    private String severity;
    private String timestamp;
}