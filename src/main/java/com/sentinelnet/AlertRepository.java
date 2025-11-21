package com.sentinelnet;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface AlertRepository extends JpaRepository<PersistentAlert, Long> {
    List<PersistentAlert> findTop50ByOrderByIdDesc();
}