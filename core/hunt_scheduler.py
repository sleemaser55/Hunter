
import schedule
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional

class HuntScheduler:
    def __init__(self, hunt_manager):
        self.hunt_manager = hunt_manager
        self.scheduled_hunts = {}
        self._start_scheduler()
    
    def schedule_hunt(self, hunt_id: str, interval: str, filters: Dict = None, max_iterations: int = None) -> bool:
        """Schedule a hunt to run periodically with improved management"""
        if not self.hunt_manager.get_hunt(hunt_id):
            return False
            
        def run_scheduled_hunt():
            try:
                hunt = self.hunt_manager.get_hunt(hunt_id)
                if not hunt:
                    return False
                    
                new_hunt_id = self.hunt_manager.start_hunt(
                    hunt_type=hunt.type,
                    target_id=hunt.target_id,
                    target_name=hunt.target_name,
                    filters=filters or hunt.filters
                )
                return new_hunt_id
            except Exception as e:
                logger.error(f"Error in scheduled hunt {hunt_id}: {str(e)}")
                return False
            
        def run_scheduled_hunt():
            hunt = self.hunt_manager.get_hunt(hunt_id)
            new_hunt_id = self.hunt_manager.start_hunt(
                hunt_type=hunt.type,
                target_id=hunt.target_id,
                target_name=hunt.target_name,
                filters=filters or hunt.filters
            )
            return new_hunt_id
            
        schedule.every().interval = interval
        schedule.every().interval.do(run_scheduled_hunt)
        self.scheduled_hunts[hunt_id] = interval
        return True
    
    def _start_scheduler(self):
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)
        
        thread = threading.Thread(target=run_scheduler, daemon=True)
        thread.start()
