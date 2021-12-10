package com.bookshop.controllers;

import com.bookshop.base.BaseController;
import com.bookshop.dao.Category;
import com.bookshop.dao.Product;
import com.bookshop.dto.ProductDTO;
import com.bookshop.dto.ProductUpdateDTO;
import com.bookshop.dto.pagination.PaginateDTO;
import com.bookshop.exceptions.AppException;
import com.bookshop.exceptions.NotFoundException;
import com.bookshop.services.CategoryService;
import com.bookshop.services.ProductService;
import com.bookshop.specifications.GenericSpecification;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

@RestController
@RequestMapping("/api/products")
public class ProductController extends BaseController<Product> {

    @Autowired
    private ProductService productService;

    @Autowired
    private CategoryService categoryService;

    @GetMapping
    public ResponseEntity<?> getListProducts(
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "perPage", required = false) Integer perPage,
            HttpServletRequest request) {

        GenericSpecification<Product> specification = new GenericSpecification<Product>().getBasicQuery(request);

        PaginateDTO<Product> paginateProducts = productService.getList(page, perPage, specification);

        return this.resPagination(paginateProducts);
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getProductByIdOrSlug(@PathVariable("id") Object id) {
        Product product;
        try {
            Long productId = Long.parseLong((String) id);
            product = productService.findById(productId).orElse(null);

        } catch (Exception e) {
            product = productService.findBySlug(id.toString());
        }

        if (product == null) {
            throw new NotFoundException("Not found product");
        }

        return this.resSuccess(product);
    }

    @PostMapping
    @PreAuthorize("@userAuthorizer.isAdmin(authentication)")
    public ResponseEntity<?> createNewProduct(@RequestBody @Valid ProductDTO productDTO) {
        Product oldProduct = productService.findBySlug(productDTO.getTitle());
        if (oldProduct != null) {
            throw new AppException("Product has already exists");
        }

        Category category = categoryService.findById(productDTO.getCategoryId()).orElse(null);

        if (category == null) {
            throw new NotFoundException("Not found category");
        }

        Product product = productService.create(productDTO);

        return this.resSuccess(product);
    }

    @PatchMapping("/{productId}")
    @PreAuthorize("@userAuthorizer.isAdmin(authentication)")
    public ResponseEntity<?> editProduct(@RequestBody @Valid ProductUpdateDTO productUpdateDTO,
                                         @PathVariable("productId") Long productId) {
        Product product = productService.findById(productId).orElse(null);

        if (product == null) {
            throw new NotFoundException("Not found product");
        }

        if (productUpdateDTO.getCategoryId() != null) {
            Category category = categoryService.findById(productUpdateDTO.getCategoryId()).orElse(null);
            if (category == null) {
                throw new NotFoundException("Not found category");
            }
        }

        Product savedProduct = productService.update(productUpdateDTO, product);

        return this.resSuccess(savedProduct);
    }
}
