/*
 * Copyright c 2014-2024 Bjoern Kimminich  the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import  ProductDetailsComponent  from ../product-details/product-details.component
import  ActivatedRoute, Router  from @angular/router
import  ProductService  from ../Services/product.service
import  BasketService  from ../Services/basket.service
import  type AfterViewInit, Component, NgZone, type OnDestroy, ViewChild, ChangeDetectorRef  from @angular/core