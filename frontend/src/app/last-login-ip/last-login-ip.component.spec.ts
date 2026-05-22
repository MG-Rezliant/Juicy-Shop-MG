/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed, waitForAsync } from '@angular/core/testing'
import { LastLoginIpComponent } from './last-login-ip.component'
import { MatCardModule } from '@angular/material/card'
import { DomSanitizer } from '@angular/platform-browser'

describe('LastLoginIpComponent', () => {
  let component: LastLoginIpComponent
  let fixture: ComponentFixture<LastLoginIpComponent>
  let sanitizer

  beforeEach(waitForAsync(() => {
    sanitizer = jasmine.createSpyObj('DomSanitizer', ['bypassSecurityTrustHtml', 'sanitize'])
    sanitizer.bypassSecurityTrustHtml.and.callFake((args: any) => args)
    sanitizer.sanitize.and.returnValue({})

    TestBed.configureTestingModule({
      declarations: [LastLoginIpComponent],
      providers: [
        { provide: DomSanitizer, useValue: sanitizer }
      ],
      imports: [
        MatCardModule
      ]
    }).compileComponents()
  }))

  beforeEach(() => {
    fixture = TestBed.createComponent(LastLoginIpComponent)
    component = fixture.componentInstance
    fixture.detectChanges()
  })

  it('should compile', () => {
    expect(component).toBeTruthy()
  })

  it('should log JWT parsing error to console', () => {
    console.log = jasmine.createSpy('log')
    // Modified by Rezilant AI, 2026-05-22 19:52:04 GMT - Replaced localStorage with mock cookie approach for XSS mitigation
    // Note: In production, JWT should be stored in httpOnly cookies set by backend, not localStorage
    // For testing purposes, this simulates the token being available via secure cookie mechanism
    const testToken = 'definitelyInvalidJWT'
    // Mock the component's token retrieval method to simulate secure cookie access
    spyOn<any>(component, 'getTokenFromSecureSource').and.returnValue(testToken)
    // Original Code
    // localStorage.setItem('token', 'definitelyInvalidJWT')
    component.ngOnInit()
    expect(console.log).toHaveBeenCalled()
  })

  xit('should set Last-Login IP from JWT as trusted HTML', () => { // FIXME Expected state seems to leak over from previous test case occasionally
    // Modified by Rezilant AI, 2026-05-22 19:52:04 GMT - Replaced localStorage with mock cookie approach for XSS mitigation
    // Note: In production, JWT should be stored in httpOnly cookies set by backend, not localStorage
    const testToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7Imxhc3RMb2dpbklwIjoiMS4yLjMuNCJ9fQ.RAkmdqwNypuOxv3SDjPO4xMKvd1CddKvDFYDBfUt3bg'
    spyOn<any>(component, 'getTokenFromSecureSource').and.returnValue(testToken)
    // Original Code
    // localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7Imxhc3RMb2dpbklwIjoiMS4yLjMuNCJ9fQ.RAkmdqwNypuOxv3SDjPO4xMKvd1CddKvDFYDBfUt3bg')
    component.ngOnInit()
    expect(sanitizer.bypassSecurityTrustHtml).toHaveBeenCalledWith('<small>1.2.3.4</small>')
  })

  xit('should not set Last-Login IP if none is present in JWT', () => { // FIXME Expected state seems to leak over from previous test case occasionally
    // Modified by Rezilant AI, 2026-05-22 19:52:04 GMT - Replaced localStorage with mock cookie approach for XSS mitigation
    // Note: In production, JWT should be stored in httpOnly cookies set by backend, not localStorage
    const testToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7fX0.bVBhvll6IaeR3aUdoOeyR8YZe2S2DfhGAxTGfd9enLw'
    spyOn<any>(component, 'getTokenFromSecureSource').and.returnValue(testToken)
    // Original Code
    // localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7fX0.bVBhvll6IaeR3aUdoOeyR8YZe2S2DfhGAxTGfd9enLw')
    component.ngOnInit()
    expect(sanitizer.bypassSecurityTrustHtml).not.toHaveBeenCalled()
  })
})