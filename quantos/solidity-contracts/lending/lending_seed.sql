-- Seed lending_reserves table after deployment
INSERT INTO lending_reserves (
  id, asset_address, asset_symbol, asset_name, asset_icon,
  l_token_address, debt_token_address,
  ltv_bps, liquidation_threshold_bps, liquidation_penalty_bps, reserve_factor_bps,
  supply_cap, borrow_cap, can_be_collateral, can_be_borrowed,
  optimal_utilization_bps, base_rate_bps, slope1_bps, slope2_bps,
  price_usd
) VALUES (
  1, 'QTS:c49ffa02bdb365b7e5bf1655dd296b7358eebdfdbe2abb3a1998db8daddc3a68', 'QTEST', 'Quantos Test', '🔷',
  'QTS:95fa380d690ef8697cde39231a0df07aa690563b6bac92549d0615b0bae9204c', 'QTS:4f8b9e875ba46a36d527cdba650e83330ae03a86f8e2d1badb41d2bf52b0229f',
  8000, 8500, 500, 1000,
  0, 0, true, true,
  8000, 200, 400, 7500,
  1.0
) ON CONFLICT (id) DO UPDATE SET
  l_token_address = EXCLUDED.l_token_address,
  debt_token_address = EXCLUDED.debt_token_address,
  price_usd = EXCLUDED.price_usd;

INSERT INTO lending_reserves (
  id, asset_address, asset_symbol, asset_name, asset_icon,
  l_token_address, debt_token_address,
  ltv_bps, liquidation_threshold_bps, liquidation_penalty_bps, reserve_factor_bps,
  supply_cap, borrow_cap, can_be_collateral, can_be_borrowed,
  optimal_utilization_bps, base_rate_bps, slope1_bps, slope2_bps,
  price_usd
) VALUES (
  2, 'QTS:7c6e716241b00d39466021064aff611b0271c94cf9d61c2442c57b6be14206e7', 'SQTEST', 'Stable QTEST', '💎',
  'QTS:e763bf82761e4d55a5f364e61af234927f1dcfb3068d0df29b7df081642d2891', 'QTS:12a26dd55b583d4025286a5311b7741acf3928eef1a7a955de1cbd5221e64f0b',
  8500, 9000, 400, 1000,
  0, 0, true, true,
  9000, 100, 300, 6000,
  1.0
) ON CONFLICT (id) DO UPDATE SET
  l_token_address = EXCLUDED.l_token_address,
  debt_token_address = EXCLUDED.debt_token_address,
  price_usd = EXCLUDED.price_usd;

