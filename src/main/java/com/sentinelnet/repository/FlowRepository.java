package com.sentinelnet.repository;

import com.sentinelnet.model.PersistentFlow;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface FlowRepository extends JpaRepository<PersistentFlow, Long> {
    // Future: Add custom queries like findBySrcIp, findByDateRange etc.
}