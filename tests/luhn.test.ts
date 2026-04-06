import { describe, it, expect } from 'vitest';
import { luhnCheck } from '../src/utils/luhn.js';

describe('luhnCheck', () => {
  it('validates Visa test card', () => {
    expect(luhnCheck('4111111111111111')).toBe(true);
  });

  it('validates Mastercard test card', () => {
    expect(luhnCheck('5500000000000004')).toBe(true);
  });

  it('validates Amex test card', () => {
    expect(luhnCheck('378282246310005')).toBe(true);
  });

  it('rejects invalid number', () => {
    expect(luhnCheck('4111111111111112')).toBe(false);
  });

  it('rejects too-short number', () => {
    expect(luhnCheck('1234')).toBe(false);
  });

  it('handles spaces and dashes', () => {
    expect(luhnCheck('4111-1111-1111-1111')).toBe(true);
    expect(luhnCheck('4111 1111 1111 1111')).toBe(true);
  });
});
