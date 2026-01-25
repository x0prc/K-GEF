CREATE CONSTRAINT firmware_id IF NOT EXISTS ON (f:Firmware) ASSERT f.id IS UNIQUE;
CREATE CONSTRAINT function_addr IF NOT EXISTS ON (fn:Function) ASSERT fn.addr IS UNIQUE;
CREATE INDEX binary_path IF NOT EXISTS ON (b:Binary);
CREATE INDEX lib_name IF NOT EXISTS ON (l:Library);

CALL db.index.fulltext.createNodeIndex("functionNames", 
  ["Function"], ["name"]);