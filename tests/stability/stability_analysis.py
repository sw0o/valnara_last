import os
import csv
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from datetime import datetime

class StabilityAnalyzer:
    def __init__(self, csv_file):
        """
        Initialize the analyzer with the CSV file from stability test
        
        :param csv_file: Path to the CSV results file
        """
        self.csv_file = csv_file
        
        # Read CSV with robust parsing
        try:
            self.df = pd.read_csv(
                csv_file, 
                header=None,  # No header in the CSV
                names=[
                    'timestamp', 'target', 'scan_types', 'status', 
                    'duration', 'progress', 'high_risks', 'medium_risks', 
                    'low_risks', 'info_risks', 'additional_metrics'
                ]
            )
            
            # Convert timestamp to datetime
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'], errors='coerce')
            
            # Convert numeric columns
            numeric_columns = ['duration', 'high_risks', 'medium_risks', 'low_risks', 'info_risks']
            for col in numeric_columns:
                self.df[col] = pd.to_numeric(self.df[col], errors='coerce')
        
        except Exception as e:
            print(f"Error reading CSV file: {e}")
            raise
        
        # Ensure analysis directory exists
        os.makedirs('stability_analysis', exist_ok=True)
    
    def generate_performance_plots(self):
        """
        Generate comprehensive performance visualization
        """
        plt.figure(figsize=(20, 15))
        plt.suptitle('Valnara Security Scanner - Stability Test Analysis', fontsize=16)
        
        # 1. Scan Duration Distribution
        plt.subplot(2, 3, 1)
        self.df['duration'].hist(bins=20, edgecolor='black')
        plt.title('Scan Duration Distribution')
        plt.xlabel('Duration (seconds)')
        plt.ylabel('Frequency')
        
        # 2. Risks Over Scans
        plt.subplot(2, 3, 2)
        risk_columns = ['high_risks', 'medium_risks', 'low_risks', 'info_risks']
        colors = ['red', 'orange', 'blue', 'green']
        for col, color in zip(risk_columns, colors):
            plt.plot(self.df.index, self.df[col], label=col.replace('_', ' ').title(), color=color)
        plt.title('Risks Detected Across Scans')
        plt.xlabel('Scan Number')
        plt.ylabel('Number of Risks')
        plt.legend()
        
        # 3. Target URL Scanning Frequency
        plt.subplot(2, 3, 3)
        target_counts = self.df['target'].value_counts()
        target_counts.plot(kind='bar', edgecolor='black')
        plt.title('Scanned Target Frequency')
        plt.xlabel('Target URL')
        plt.ylabel('Number of Scans')
        plt.xticks(rotation=45, ha='right')
        
        # 4. Scan Types Distribution
        plt.subplot(2, 3, 4)
        self.df['scan_types'] = self.df['scan_types'].apply(lambda x: str(x))
        scan_type_counts = self.df['scan_types'].value_counts()
        plt.pie(scan_type_counts, labels=scan_type_counts.index, autopct='%1.1f%%')
        plt.title('Scan Types Distribution')
        
        # 5. Scan Status Breakdown
        plt.subplot(2, 3, 5)
        status_counts = self.df['status'].value_counts()
        plt.pie(status_counts, labels=status_counts.index, autopct='%1.1f%%')
        plt.title('Scan Status Distribution')
        
        # 6. Duration vs Risks Scatter
        plt.subplot(2, 3, 6)
        plt.scatter(self.df['duration'], self.df['high_risks'], 
                    alpha=0.7, c='red', label='High Risks')
        plt.scatter(self.df['duration'], self.df['medium_risks'], 
                    alpha=0.7, c='orange', label='Medium Risks')
        plt.title('Scan Duration vs Risks')
        plt.xlabel('Scan Duration (seconds)')
        plt.ylabel('Number of Risks')
        plt.legend()
        
        plt.tight_layout()
        plt.savefig('stability_analysis/performance_analysis.png')
        plt.close()
    
    def generate_summary_report(self):
        """
        Generate a comprehensive text summary of the stability test
        """
        with open('stability_analysis/summary_report.txt', 'w') as f:
            f.write("VALNARA SECURITY SCANNER - STABILITY TEST ANALYSIS\n")
            f.write("="*50 + "\n\n")
            
            # Basic Statistics
            f.write("1. SCAN OVERVIEW\n")
            f.write("-"*20 + "\n")
            f.write(f"Total Scans: {len(self.df)}\n")
            f.write(f"Unique Targets Scanned: {self.df['target'].nunique()}\n")
            f.write(f"Scan Success Rate: {(self.df['status'] == 'completed').mean()*100:.2f}%\n\n")
            
            # Performance Metrics
            f.write("2. PERFORMANCE METRICS\n")
            f.write("-"*20 + "\n")
            f.write(f"Average Scan Duration: {self.df['duration'].mean():.2f} seconds\n")
            f.write(f"Scan Duration Std Dev: {self.df['duration'].std():.2f} seconds\n")
            f.write(f"Minimum Scan Duration: {self.df['duration'].min():.2f} seconds\n")
            f.write(f"Maximum Scan Duration: {self.df['duration'].max():.2f} seconds\n\n")
            
            # Vulnerability Summary
            f.write("3. VULNERABILITY SUMMARY\n")
            f.write("-"*20 + "\n")
            for risk in ['high_risks', 'medium_risks', 'low_risks', 'info_risks']:
                risk_name = risk.replace('_', ' ').title()
                total_risks = self.df[risk].sum()
                avg_risks_per_scan = self.df[risk].mean()
                f.write(f"Total {risk_name}: {total_risks}\n")
                f.write(f"Average {risk_name} per Scan: {avg_risks_per_scan:.2f}\n")
            
            f.write("\n4. SCAN TYPE ANALYSIS\n")
            f.write("-"*20 + "\n")
            scan_type_summary = self.df['scan_types'].value_counts()
            for scan_type, count in scan_type_summary.items():
                f.write(f"Scan Type {scan_type}: {count} times\n")
    
    def run_full_analysis(self):
        """
        Run complete analysis and generate all outputs
        """
        print("Generating Performance Plots...")
        self.generate_performance_plots()
        
        print("Generating Summary Report...")
        self.generate_summary_report()
        
        print("Analysis Complete!")
        print("Please check 'stability_analysis' directory for results.")

def main():
    # Find the most recent stability test results
    results_dir = 'stability_results'
    csv_files = [f for f in os.listdir(results_dir) if f.endswith('.csv')]
    
    if not csv_files:
        print("No stability test results found!")
        return
    
    # Use the most recent CSV file
    latest_csv = os.path.join(results_dir, max(csv_files))
    
    # Run analysis
    analyzer = StabilityAnalyzer(latest_csv)
    analyzer.run_full_analysis()

if __name__ == '__main__':
    main()