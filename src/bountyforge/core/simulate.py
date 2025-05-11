

class Simulation:
    def __init__(self, simulation_id: str):
        self.simulation_id = simulation_id
        self.simulation_data = None

    def run_simulation(self):
        # Placeholder for simulation logic
        self.simulation_data = {"result": "success", "data": {}}

    def get_results(self):
        if self.simulation_data is None:
            raise ValueError("Simulation has not been run yet.")
        return self.simulation_data
