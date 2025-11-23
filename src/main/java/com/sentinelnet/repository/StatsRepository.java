package com.sentinelnet.repository;

import com.sentinelnet.model.TrafficStats;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface StatsRepository extends JpaRepository<TrafficStats, Long> {
}