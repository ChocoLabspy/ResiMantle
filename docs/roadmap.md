# Roadmap

ResiMantle is being developed in 7 distinct stages.

## Stage 1: Concept and Repository ✅
- [x] Create powerful README and branding
- [x] Define architecture (9 layers)
- [x] Establish ethical limits
- [x] Create the initial professional monorepo structure

## Stage 2: MVP Local 🚧
- [ ] Implement basic CLI (`resimantle init`, `scan`, `report`)
- [ ] Implement `resimantle.config.json` loader
- [ ] Basic Surface Coat scanning (without modifying code)
- [ ] Fictional secrets detection for testing
- [ ] Basic canaries generation

## Stage 3: Runtime Wrapper
- [ ] Implement `resimantle run` for Node.js apps
- [ ] Register endpoints/commands accessed at runtime
- [ ] Create initial behavior profile mapping
- [ ] Detect rarely accessed routes

## Stage 4: Discord Bot Protection
- [ ] Detect sensitive bot commands
- [ ] Monitor command usage patterns
- [ ] Protect administrative commands externally
- [ ] Detect excessive permissions

## Stage 5: AI Proxy
- [ ] Proxy layer for model API calls
- [ ] Basic prompt injection detection
- [ ] Secure logging of AI interactions
- [ ] Tool usage control and enforcement

## Stage 6: Advanced Policy Engine
- [ ] Context-aware decision making
- [ ] Implement all Gatekeeper levels (ALLOW / LOG / LIMIT / APPROVE / BLOCK)
- [ ] Natural language explanation generation for decisions

## Stage 7: Web Dashboard
- [ ] Visual risk map
- [ ] Anomaly history viewer
- [ ] Protected zones management interface
- [ ] Security score calculation
