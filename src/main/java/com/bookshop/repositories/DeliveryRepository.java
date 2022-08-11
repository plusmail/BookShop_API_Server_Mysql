package com.bookshop.repositories;

import com.bookshop.dao.Delivery;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.stereotype.Repository;

@Repository
@EnableJpaRepositories
public interface DeliveryRepository extends JpaRepository<Delivery, Long> {
    Delivery findByIndexId(String indexId);
}
