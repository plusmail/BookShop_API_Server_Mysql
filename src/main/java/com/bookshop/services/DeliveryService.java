package com.bookshop.services;

import com.bookshop.dao.Delivery;

import java.util.List;

public interface DeliveryService {
    Long countAll();

    Delivery findById(Long deliveryId);

    Delivery findByIndexId(String indexId);

    Delivery findByAddedToCartState();

    Delivery findByWaitingToConfirmState();

    Delivery findByDeliveredState();

    Delivery findByCancelState();

    List<Delivery> findAll();

    void seedData();
}
