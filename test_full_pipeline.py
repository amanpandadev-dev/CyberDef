"""
Full Pipeline Test with logevent1.csv

Tests the complete pipeline:
1. Parse
2. Normalize
3. Deduplicate
4. Deterministic Detection (Tier 1)
5. Threat State Update
6. Chunking
7. Results Analysis
"""

import json
import time
from datetime import date
from pathlib import Path
from uuid import uuid4

from core.config import get_settings
from core.logging import get_logger
from log_parser import ParserRegistry
from normalization.deduplication import Deduplicator
from normalization.service import NormalizationService
from rules_engine.engine import DeterministicEngine
from threat_state.store import get_threat_state_store, _stores
from chunking.service import ChunkingService
from shared_models.events import RawEventRow

logger = get_logger(__name__)


def test_full_pipeline():
    """Test the complete pipeline with logevent1.csv"""
    
    settings = get_settings()
    test_file = Path("logevent1.csv")
    
    if not test_file.exists():
        logger.error(f"Test file not found: {test_file}")
        return False
    
    logger.info("=" * 100)
    logger.info("FULL PIPELINE TEST: logevent1.csv")
    logger.info("=" * 100)
    
    # Clear threat state cache
    _stores.clear()
    
    file_id = uuid4()
    results = {
        "file_id": str(file_id),
        "filename": test_file.name,
        "file_size_bytes": test_file.stat().st_size,
        "stages": {},
    }
    
    try:
        # ========== STAGE 1: PARSE ==========
        logger.info("\n" + "=" * 100)
        logger.info("STAGE 1: PARSING")
        logger.info("=" * 100)
        
        start_time = time.time()
        
        # Read raw syslog file
        with open(test_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        logger.info(f"Read {len(lines)} log lines from file")
        
        # Create synthetic CSV rows for parser detection
        # The file is actually syslog format, so we'll create a minimal CSV structure
        synthetic_rows = [{"raw_log": line} for line in lines[:5]]
        
        parser = ParserRegistry.detect_parser(["raw_log"], synthetic_rows)
        logger.info(f"Detected parser: {parser.name} (vendor: {parser.vendor})")
        
        # Parse all lines
        raw_rows = []
        for row_num, line in enumerate(lines, start=1):
            raw_rows.append(RawEventRow(
                file_id=file_id,
                row_number=row_num,
                raw_data={"raw_log": line}
            ))
        
        parsed_events = parser.parse_batch(raw_rows)
        parse_time = time.time() - start_time
        
        results["stages"]["parse"] = {
            "duration_ms": int(parse_time * 1000),
            "raw_rows": len(raw_rows),
            "parsed_events": len(parsed_events),
            "parse_errors": parser.rows_failed,
            "success_rate": parser.get_stats()["success_rate"],
        }
        
        logger.info(f"Parse complete | raw_rows={len(raw_rows)}, parsed={len(parsed_events)}, "
                   f"errors={parser.rows_failed}, time={parse_time:.2f}s")
        
        # ========== STAGE 2: NORMALIZE ==========
        logger.info("\n" + "=" * 100)
        logger.info("STAGE 2: NORMALIZATION")
        logger.info("=" * 100)
        
        start_time = time.time()
        
        normalizer = NormalizationService()
        event_batch = normalizer.normalize_batch_parallel(parsed_events)
        normalize_time = time.time() - start_time
        
        results["stages"]["normalize"] = {
            "duration_ms": int(normalize_time * 1000),
            "normalized_events": len(event_batch.events),
            "normalization_errors": normalizer.normalization_errors,
            "success_rate": normalizer.get_stats()["success_rate"],
        }
        
        logger.info(f"Normalize complete | events={len(event_batch.events)}, "
                   f"errors={normalizer.normalization_errors}, time={normalize_time:.2f}s")
        
        # ========== STAGE 3: DEDUPLICATE ==========
        logger.info("\n" + "=" * 100)
        logger.info("STAGE 3: DEDUPLICATION")
        logger.info("=" * 100)
        
        start_time = time.time()
        
        deduplicator = Deduplicator()
        deduped_events = deduplicator.deduplicate(event_batch.events)
        dedupe_time = time.time() - start_time
        
        duplicates_removed = len(event_batch.events) - len(deduped_events)
        reduction_pct = (duplicates_removed / len(event_batch.events) * 100) if event_batch.events else 0
        
        results["stages"]["deduplicate"] = {
            "duration_ms": int(dedupe_time * 1000),
            "input_events": len(event_batch.events),
            "deduplicated_events": len(deduped_events),
            "duplicates_removed": duplicates_removed,
            "reduction_percentage": reduction_pct,
        }
        
        logger.info(f"Deduplicate complete | input={len(event_batch.events)}, "
                   f"output={len(deduped_events)}, removed={duplicates_removed} ({reduction_pct:.1f}%), "
                   f"time={dedupe_time:.2f}s")
        
        # ========== STAGE 4: DETERMINISTIC DETECTION ==========
        logger.info("\n" + "=" * 100)
        logger.info("STAGE 4: DETERMINISTIC DETECTION (TIER 1)")
        logger.info("=" * 100)
        
        start_time = time.time()
        
        engine = DeterministicEngine()
        detection_result = engine.scan(deduped_events)
        detection_time = time.time() - start_time
        
        results["stages"]["detection"] = {
            "duration_ms": int(detection_time * 1000),
            "events_scanned": detection_result.events_scanned,
            "matches_found": len(detection_result.matches),
            "threats_grouped": len(detection_result.threats),
            "threats_by_category": detection_result.threats_by_category,
            "threats_by_severity": detection_result.threats_by_severity,
            "unique_attacker_ips": detection_result.unique_attacker_ips,
            "needs_ai_review": detection_result.needs_ai_review,
        }
        
        logger.info(f"Detection complete | events_scanned={detection_result.events_scanned}, "
                   f"matches={len(detection_result.matches)}, threats={len(detection_result.threats)}, "
                   f"time={detection_time:.2f}s")
        
        if detection_result.threats:
            logger.info(f"Threats by category: {detection_result.threats_by_category}")
            logger.info(f"Threats by severity: {detection_result.threats_by_severity}")
            logger.info(f"Attacker IPs: {detection_result.unique_attacker_ips}")
            
            # Show sample threats
            for i, threat in enumerate(detection_result.threats[:5], 1):
                logger.info(f"  Threat {i}: {threat.rule_name} ({threat.severity.value}) - "
                           f"{threat.match_count} matches from {threat.src_ip}")
        
        # ========== STAGE 5: THREAT STATE UPDATE ==========
        logger.info("\n" + "=" * 100)
        logger.info("STAGE 5: THREAT STATE UPDATE")
        logger.info("=" * 100)
        
        start_time = time.time()
        
        threat_store = get_threat_state_store(date.today())
        threat_store.update_from_batch(deduped_events, detection_result)
        state_time = time.time() - start_time
        
        summary = threat_store.get_day_summary()
        
        results["stages"]["threat_state"] = {
            "duration_ms": int(state_time * 1000),
            "total_events": summary["total_events"],
            "unique_ips": summary["unique_ips"],
            "unique_attackers": summary["unique_attackers"],
            "batches_processed": summary["batches_processed"],
            "threats_by_category": summary["threats_by_category"],
        }
        
        logger.info(f"Threat state updated | total_events={summary['total_events']}, "
                   f"unique_ips={summary['unique_ips']}, unique_attackers={summary['unique_attackers']}, "
                   f"time={state_time:.2f}s")
        
        # ========== STAGE 6: CHUNKING ==========
        logger.info("\n" + "=" * 100)
        logger.info("STAGE 6: CHUNKING")
        logger.info("=" * 100)
        
        start_time = time.time()
        
        import asyncio
        chunking_service = ChunkingService()
        chunks = asyncio.run(chunking_service.chunk_events(deduped_events, file_id))
        chunking_time = time.time() - start_time
        
        results["stages"]["chunking"] = {
            "duration_ms": int(chunking_time * 1000),
            "total_chunks": len(chunks),
            "events_chunked": sum(len(c.events) for c in chunks),
        }
        
        logger.info(f"Chunking complete | chunks={len(chunks)}, "
                   f"events_chunked={sum(len(c.events) for c in chunks)}, time={chunking_time:.2f}s")
        
        # ========== RESULTS SUMMARY ==========
        logger.info("\n" + "=" * 100)
        logger.info("PIPELINE RESULTS SUMMARY")
        logger.info("=" * 100)
        
        total_time = (parse_time + normalize_time + dedupe_time + detection_time + 
                     state_time + chunking_time)
        
        logger.info(f"\nFile: {test_file.name} ({results['file_size_bytes']} bytes)")
        logger.info(f"File ID: {file_id}")
        logger.info(f"\nStage Breakdown:")
        logger.info(f"  1. Parse:       {parse_time:7.2f}s ({parse_time/total_time*100:5.1f}%)")
        logger.info(f"  2. Normalize:   {normalize_time:7.2f}s ({normalize_time/total_time*100:5.1f}%)")
        logger.info(f"  3. Deduplicate: {dedupe_time:7.2f}s ({dedupe_time/total_time*100:5.1f}%)")
        logger.info(f"  4. Detection:   {detection_time:7.2f}s ({detection_time/total_time*100:5.1f}%)")
        logger.info(f"  5. Threat State:{state_time:7.2f}s ({state_time/total_time*100:5.1f}%)")
        logger.info(f"  6. Chunking:    {chunking_time:7.2f}s ({chunking_time/total_time*100:5.1f}%)")
        logger.info(f"  ─────────────────────────────")
        logger.info(f"  Total:          {total_time:7.2f}s")
        
        logger.info(f"\nData Flow:")
        logger.info(f"  Raw rows:           {len(raw_rows):6d}")
        logger.info(f"  Parsed events:      {len(parsed_events):6d}")
        logger.info(f"  Normalized events:  {len(event_batch.events):6d}")
        logger.info(f"  Deduplicated:       {len(deduped_events):6d} (removed {duplicates_removed})")
        logger.info(f"  Chunks created:     {len(chunks):6d}")
        
        logger.info(f"\nDetection Results:")
        logger.info(f"  Matches found:      {len(detection_result.matches):6d}")
        logger.info(f"  Threats grouped:    {len(detection_result.threats):6d}")
        logger.info(f"  Unique attackers:   {len(detection_result.unique_attacker_ips):6d}")
        logger.info(f"  Needs AI review:    {detection_result.needs_ai_review}")
        
        logger.info(f"\nThreat State:")
        logger.info(f"  Total events:       {summary['total_events']:6d}")
        logger.info(f"  Unique IPs:         {summary['unique_ips']:6d}")
        logger.info(f"  Unique attackers:   {summary['unique_attackers']:6d}")
        logger.info(f"  Batches processed:  {summary['batches_processed']:6d}")
        
        # ========== SAVE RESULTS ==========
        results["total_time_ms"] = int(total_time * 1000)
        results["success"] = True
        
        report_path = Path("data/processed/pipeline_test_report.json")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with report_path.open("w") as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"\n✓ Report saved to: {report_path}")
        logger.info("=" * 100)
        logger.info("✓ PIPELINE TEST COMPLETED SUCCESSFULLY")
        logger.info("=" * 100)
        
        return True
        
    except Exception as e:
        logger.error(f"Pipeline test failed: {e}", exc_info=True)
        results["success"] = False
        results["error"] = str(e)
        
        report_path = Path("data/processed/pipeline_test_report.json")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with report_path.open("w") as f:
            json.dump(results, f, indent=2, default=str)
        
        return False


if __name__ == "__main__":
    success = test_full_pipeline()
    exit(0 if success else 1)
