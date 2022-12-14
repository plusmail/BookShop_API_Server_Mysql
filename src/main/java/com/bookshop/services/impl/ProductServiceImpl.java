package com.bookshop.services.impl;

import com.bookshop.base.BasePagination;
import com.bookshop.dao.Category;
import com.bookshop.dao.Product;
import com.bookshop.dto.ProductDTO;
import com.bookshop.dto.ProductUpdateDTO;
import com.bookshop.dto.pagination.PaginateDTO;
import com.bookshop.helpers.StringHelper;
import com.bookshop.repositories.CategoryRepository;
import com.bookshop.repositories.ProductRepository;
import com.bookshop.services.ProductService;
import com.bookshop.specifications.GenericSpecification;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductServiceImpl extends BasePagination<Product, ProductRepository> implements ProductService {

    @Autowired
    private ModelMapper mapper;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private CategoryRepository categoryRepository;

    @Autowired
    public ProductServiceImpl(ProductRepository productRepository) {
        super(productRepository);
    }

    @Override
    public List<Product> findAll(GenericSpecification<Product> specification) {
        return productRepository.findAll(specification);
    }

    @Override
    public Product findById(Long productId) {
        return productRepository.findById(productId).orElse(null);
    }

    @Override
    public List<Product> findByIdsWithOrder(List<Integer> whereIds, String positionIds, Pageable pageable) {
        return productRepository.findByIdsWithOrder(whereIds, positionIds, pageable);
    }

    @Override
    public Product findBySlug(String slug) {
        return productRepository.findBySlug(StringHelper.toSlug(slug));
    }

    @Override
    public Product create(ProductDTO productDTO) {
        Product product = mapper.map(productDTO, Product.class);
        Category category = categoryRepository.findById(productDTO.getCategoryId()).orElse(null);
        product.setCategory(category);
        return productRepository.save(product);
    }

    @Override
    public Product update(ProductUpdateDTO productUpdateDTO, Product currentProduct) {
        Product updated = mapper.map(productUpdateDTO, Product.class);
        mapper.map(updated, currentProduct);
        if (productUpdateDTO.getCategoryId() != null) {
            currentProduct.getCategory().setId(productUpdateDTO.getCategoryId());
        }
        return productRepository.save(currentProduct);
    }

    @Override
    public void update(Product product) {
        productRepository.save(product);
    }

    @Override
    public void deleteById(Long productId) {
        productRepository.deleteById(productId);
    }

    @Override
    public PaginateDTO<Product> getList(Integer page, Integer perPage, GenericSpecification<Product> specification) {
        return this.paginate(page, perPage, specification);
    }
}
