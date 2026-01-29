.PHONY: help build test clean install neo4j-start neo4j-stop full-pipeline

# Config
FIRMWARE ?= data/firmware/tplink.bin
EXTRACTED ?= extracted
ANALYSIS ?= analysis
FIRMWARE_ID ?= F001
GHIDRA_HOME ?= /opt/ghidra
NEO4J_URI ?= bolt://localhost:7687

# Default target
all: build test

help:
	@echo "Available targets:"
	@echo "  make build          - Compile fwcli"
	@echo "  make install        - Install fwcli globally"
	@echo "  make test           - Run full pipeline on test firmware"
	@echo "  make full-pipeline  - Run complete analysis → Neo4j"
	@echo "  make neo4j-start    - Start Neo4j Docker container"
	@echo "  make neo4j-stop     - Stop Neo4j container"
	@echo "  make clean          - Clean all generated files"
	@echo ""
	@echo "Environment variables:"
	@echo "  FIRMWARE=...     - Firmware file (default: data/firmware/tplink.bin)"
	@echo "  GHIDRA_HOME=...  - Ghidra path (default: /opt/ghidra)"
	@echo "  NEO4J_URI=...    - Neo4j bolt URI"

build:
	cargo build --release

install:
	cargo install --force --path .

# Neo4j Docker management
neo4j-start:
	docker run -d \
		--name fwgraph-neo4j \
		-p 7474:7474 \
		-p 7687:7687 \
		-v $(PWD)/neo4j:/data \
		-e NEO4J_AUTH=neo4j/password \
		neo4j:latest
	sleep 10
	docker exec fwgraph-neo4j cypher-shell -u neo4j -p password < neo4j/schema.cypher

neo4j-stop:
	docker stop fwgraph-neo4j || true
	docker rm fwgraph-neo4j || true

# Full pipeline
full-pipeline: clean-extract clean-analysis unpack index analyze graph-build graph-tag neo4j-load neo4j-query

# Pipeline steps
unpack:
	@echo "Unpacking firmware..."
	mkdir -p $(EXTRACTED)
	fwcli unpack $(FIRMWARE) $(EXTRACTED)

index:
	@echo "Indexing binaries..."
	fwcli index $(EXTRACTED)

analyze:
	@echo "Running Ghidra analysis..."
	mkdir -p $(ANALYSIS)
	fwcli analyze $(EXTRACTED) $(ANALYSIS) -g $(GHIDRA_HOME)

graph-build:
	@echo "Building graph..."
	fwcli graph-build $(ANALYSIS) --firmware-id $(FIRMWARE_ID)

graph-tag:
	@echo "Semantic tagging..."
	fwcli graph-tag $(ANALYSIS)

neo4j-load:
	@echo "Loading to Neo4j..."
	fwcli neo4j-load $(ANALYSIS) --firmware-id $(FIRMWARE_ID)

neo4j-query:
	@echo "Neo4j security queries..."
	fwcli neo4j-query --firmware-id $(FIRMWARE_ID)

# Test / validation
test: unpack index analyze graph-build graph-tag
	@echo "Pipeline test complete!"

# Cleanup
clean:
	cargo clean
	$(MAKE) clean-extract
	$(MAKE) clean-analysis
	$(MAKE) clean-neo4j

clean-extract:
	rm -rf $(EXTRACTED)

clean-analysis:
	rm -rf $(ANALYSIS)

clean-neo4j:
	docker exec fwgraph-neo4j cypher-shell -u neo4j -p password \
		-e "MATCH (f:Firmware {id: '$(FIRMWARE_ID)'}) DETACH DELETE f" || true
