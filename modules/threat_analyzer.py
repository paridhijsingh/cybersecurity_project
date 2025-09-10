"""
Threat Analyzer Module
Provides analysis capabilities for cybersecurity threat datasets including statistical analysis,
trend identification, and threat intelligence insights.
"""

import pandas as pd
import numpy as np
import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict

# Optional visualization imports
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    HAS_VISUALIZATION = True
except ImportError:
    HAS_VISUALIZATION = False


class ThreatAnalyzer:
    """Threat analysis functionality for cybersecurity datasets."""
    
    def __init__(self):
        """Initialize the threat analyzer."""
        self.dataset = None
        self.analysis_results = {}
        self.insights = []
        self.trends = {}
    
    def display_menu(self):
        """Display threat analysis menu options."""
        print("\n" + "-"*40)
        print("THREAT ANALYSIS OPTIONS")
        print("-"*40)
        print("1. Load Dataset")
        print("2. Dataset Overview")
        print("3. Attack Type Analysis")
        print("4. Geographic Analysis")
        print("5. Industry Impact Analysis")
        print("6. Temporal Trends")
        print("7. Financial Impact Analysis")
        print("8. Vulnerability Analysis")
        print("9. Defense Effectiveness")
        print("10. Data Visualization")
        print("11. Generate Threat Intelligence Report")
        print("12. Export Analysis Results")
        print("13. Back to Main Menu")
        print("-"*40)
    
    def get_user_choice(self):
        """Get user's menu choice with validation."""
        while True:
            try:
                choice = input("\nEnter your choice (1-13): ").strip()
                if choice in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13']:
                    return int(choice)
                else:
                    print("Invalid choice. Please enter a number between 1-13.")
            except KeyboardInterrupt:
                return 13
            except Exception as e:
                print(f"Error: {e}. Please try again.")
    
    def load_dataset(self):
        """Load the cybersecurity threats dataset."""
        print("\n--- LOAD DATASET ---")
        
        # Default to the Global_Cybersecurity_Threats_2015-2024.csv file
        default_file = "Global_Cybersecurity_Threats_2015-2024.csv"
        
        file_path = input(f"Enter dataset path (default: {default_file}): ").strip()
        if not file_path:
            file_path = default_file
        
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found.")
            return
        
        try:
            print(f"Loading dataset from {file_path}...")
            self.dataset = pd.read_csv(file_path)
            
            # Clean and preprocess the data
            self.preprocess_dataset()
            
            print(f"Dataset loaded successfully!")
            print(f"Shape: {self.dataset.shape}")
            print(f"Columns: {list(self.dataset.columns)}")
            
        except Exception as e:
            print(f"Error loading dataset: {e}")
    
    def preprocess_dataset(self):
        """Preprocess the dataset for analysis."""
        if self.dataset is None:
            return
        
        # Convert numeric columns
        numeric_columns = ['Financial Loss (in Million $)', 'Number of Affected Users', 'Incident Resolution Time (in Hours)']
        for col in numeric_columns:
            if col in self.dataset.columns:
                self.dataset[col] = pd.to_numeric(self.dataset[col], errors='coerce')
        
        # Convert Year to datetime for better analysis
        if 'Year' in self.dataset.columns:
            self.dataset['Year'] = pd.to_numeric(self.dataset['Year'], errors='coerce')
        
        # Fill missing values
        self.dataset = self.dataset.fillna('Unknown')
        
        print("Dataset preprocessed successfully!")
    
    def dataset_overview(self):
        """Provide an overview of the dataset."""
        print("\n--- DATASET OVERVIEW ---")
        
        if self.dataset is None:
            print("No dataset loaded. Please load a dataset first.")
            return
        
        print(f"Dataset Shape: {self.dataset.shape}")
        print(f"Total Records: {len(self.dataset)}")
        print(f"Date Range: {self.dataset['Year'].min()} - {self.dataset['Year'].max()}")
        
        print("\nColumn Information:")
        for col in self.dataset.columns:
            print(f"  {col}: {self.dataset[col].dtype}")
        
        print("\nMissing Values:")
        missing = self.dataset.isnull().sum()
        for col, count in missing.items():
            if count > 0:
                print(f"  {col}: {count}")
        
        print("\nFirst 5 records:")
        print(self.dataset.head())
    
    def attack_type_analysis(self):
        """Analyze attack types and their characteristics."""
        print("\n--- ATTACK TYPE ANALYSIS ---")
        
        if self.dataset is None:
            print("No dataset loaded. Please load a dataset first.")
            return
        
        attack_type_col = 'Attack Type'
        if attack_type_col not in self.dataset.columns:
            print(f"Column '{attack_type_col}' not found in dataset.")
            return
        
        # Count attack types
        attack_counts = self.dataset[attack_type_col].value_counts()
        print("\nAttack Type Distribution:")
        for attack_type, count in attack_counts.items():
            percentage = (count / len(self.dataset)) * 100
            print(f"  {attack_type}: {count} ({percentage:.1f}%)")
        
        # Financial impact by attack type
        if 'Financial Loss (in Million $)' in self.dataset.columns:
            financial_by_attack = self.dataset.groupby(attack_type_col)['Financial Loss (in Million $)'].agg(['sum', 'mean', 'count'])
            print("\nFinancial Impact by Attack Type:")
            print(financial_by_attack)
        
        # Users affected by attack type
        if 'Number of Affected Users' in self.dataset.columns:
            users_by_attack = self.dataset.groupby(attack_type_col)['Number of Affected Users'].agg(['sum', 'mean'])
            print("\nUsers Affected by Attack Type:")
            print(users_by_attack)
        
        self.analysis_results['attack_types'] = {
            'distribution': attack_counts.to_dict(),
            'financial_impact': financial_by_attack.to_dict() if 'Financial Loss (in Million $)' in self.dataset.columns else None,
            'users_affected': users_by_attack.to_dict() if 'Number of Affected Users' in self.dataset.columns else None
        }
    
    def geographic_analysis(self):
        """Analyze threats by geographic location."""
        print("\n--- GEOGRAPHIC ANALYSIS ---")
        
        if self.dataset is None:
            print("No dataset loaded. Please load a dataset first.")
            return
        
        country_col = 'Country'
        if country_col not in self.dataset.columns:
            print(f"Column '{country_col}' not found in dataset.")
            return
        
        # Country-wise threat distribution
        country_counts = self.dataset[country_col].value_counts()
        print("\nTop 10 Countries by Threat Count:")
        for country, count in country_counts.head(10).items():
            percentage = (count / len(self.dataset)) * 100
            print(f"  {country}: {count} ({percentage:.1f}%)")
        
        # Financial impact by country
        if 'Financial Loss (in Million $)' in self.dataset.columns:
            financial_by_country = self.dataset.groupby(country_col)['Financial Loss (in Million $)'].agg(['sum', 'mean']).sort_values('sum', ascending=False)
            print("\nTop 10 Countries by Financial Impact:")
            print(financial_by_country.head(10))
        
        # Attack types by country
        print("\nAttack Types by Top Countries:")
        top_countries = country_counts.head(5).index
        for country in top_countries:
            country_data = self.dataset[self.dataset[country_col] == country]
            attack_dist = country_data['Attack Type'].value_counts()
            print(f"\n{country}:")
            for attack, count in attack_dist.head(3).items():
                print(f"  {attack}: {count}")
        
        self.analysis_results['geographic'] = {
            'country_distribution': country_counts.to_dict(),
            'financial_by_country': financial_by_country.to_dict() if 'Financial Loss (in Million $)' in self.dataset.columns else None
        }
    
    def industry_impact_analysis(self):
        """Analyze impact on different industries."""
        print("\n--- INDUSTRY IMPACT ANALYSIS ---")
        
        if self.dataset is None:
            print("No dataset loaded. Please load a dataset first.")
            return
        
        industry_col = 'Target Industry'
        if industry_col not in self.dataset.columns:
            print(f"Column '{industry_col}' not found in dataset.")
            return
        
        # Industry threat distribution
        industry_counts = self.dataset[industry_col].value_counts()
        print("\nThreats by Industry:")
        for industry, count in industry_counts.items():
            percentage = (count / len(self.dataset)) * 100
            print(f"  {industry}: {count} ({percentage:.1f}%)")
        
        # Financial impact by industry
        if 'Financial Loss (in Million $)' in self.dataset.columns:
            financial_by_industry = self.dataset.groupby(industry_col)['Financial Loss (in Million $)'].agg(['sum', 'mean']).sort_values('sum', ascending=False)
            print("\nFinancial Impact by Industry:")
            print(financial_by_industry)
        
        # Most common attack types per industry
        print("\nMost Common Attack Types by Industry:")
        for industry in industry_counts.head(5).index:
            industry_data = self.dataset[self.dataset[industry_col] == industry]
            attack_dist = industry_data['Attack Type'].value_counts()
            print(f"\n{industry}:")
            for attack, count in attack_dist.head(3).items():
                print(f"  {attack}: {count}")
        
        self.analysis_results['industry'] = {
            'industry_distribution': industry_counts.to_dict(),
            'financial_by_industry': financial_by_industry.to_dict() if 'Financial Loss (in Million $)' in self.dataset.columns else None
        }
    
    def temporal_trends(self):
        """Analyze temporal trends in cybersecurity threats."""
        print("\n--- TEMPORAL TRENDS ANALYSIS ---")
        
        if self.dataset is None:
            print("No dataset loaded. Please load a dataset first.")
            return
        
        year_col = 'Year'
        if year_col not in self.dataset.columns:
            print(f"Column '{year_col}' not found in dataset.")
            return
        
        # Threats by year
        yearly_counts = self.dataset[year_col].value_counts().sort_index()
        print("\nThreats by Year:")
        for year, count in yearly_counts.items():
            print(f"  {year}: {count}")
        
        # Financial impact trends
        if 'Financial Loss (in Million $)' in self.dataset.columns:
            yearly_financial = self.dataset.groupby(year_col)['Financial Loss (in Million $)'].agg(['sum', 'mean'])
            print("\nFinancial Impact Trends:")
            print(yearly_financial)
        
        # Attack type trends over time
        print("\nAttack Type Trends (Top 5 by Year):")
        for year in sorted(self.dataset[year_col].unique()):
            if pd.notna(year):
                year_data = self.dataset[self.dataset[year_col] == year]
                attack_dist = year_data['Attack Type'].value_counts()
                print(f"\n{year}:")
                for attack, count in attack_dist.head(5).items():
                    print(f"  {attack}: {count}")
        
        self.analysis_results['temporal'] = {
            'yearly_distribution': yearly_counts.to_dict(),
            'financial_trends': yearly_financial.to_dict() if 'Financial Loss (in Million $)' in self.dataset.columns else None
        }
    
    def financial_impact_analysis(self):
        """Analyze financial impact of cybersecurity threats."""
        print("\n--- FINANCIAL IMPACT ANALYSIS ---")
        
        if self.dataset is None:
            print("No dataset loaded. Please load a dataset first.")
            return
        
        financial_col = 'Financial Loss (in Million $)'
        if financial_col not in self.dataset.columns:
            print(f"Column '{financial_col}' not found in dataset.")
            return
        
        # Basic financial statistics
        financial_data = self.dataset[financial_col].dropna()
        print(f"\nFinancial Impact Statistics:")
        print(f"  Total Loss: ${financial_data.sum():.2f} million")
        print(f"  Average Loss: ${financial_data.mean():.2f} million")
        print(f"  Median Loss: ${financial_data.median():.2f} million")
        print(f"  Maximum Loss: ${financial_data.max():.2f} million")
        print(f"  Minimum Loss: ${financial_data.min():.2f} million")
        
        # Top 10 most expensive incidents
        top_incidents = self.dataset.nlargest(10, financial_col)[['Country', 'Year', 'Attack Type', 'Target Industry', financial_col]]
        print(f"\nTop 10 Most Expensive Incidents:")
        print(top_incidents.to_string(index=False))
        
        # Financial impact by attack type
        financial_by_attack = self.dataset.groupby('Attack Type')[financial_col].agg(['sum', 'mean', 'count']).sort_values('sum', ascending=False)
        print(f"\nFinancial Impact by Attack Type:")
        print(financial_by_attack)
        
        self.analysis_results['financial'] = {
            'statistics': {
                'total': financial_data.sum(),
                'average': financial_data.mean(),
                'median': financial_data.median(),
                'max': financial_data.max(),
                'min': financial_data.min()
            },
            'by_attack_type': financial_by_attack.to_dict()
        }
    
    def vulnerability_analysis(self):
        """Analyze security vulnerabilities and their impact."""
        print("\n--- VULNERABILITY ANALYSIS ---")
        
        if self.dataset is None:
            print("No dataset loaded. Please load a dataset first.")
            return
        
        vuln_col = 'Security Vulnerability Type'
        if vuln_col not in self.dataset.columns:
            print(f"Column '{vuln_col}' not found in dataset.")
            return
        
        # Vulnerability distribution
        vuln_counts = self.dataset[vuln_col].value_counts()
        print("\nVulnerability Types:")
        for vuln, count in vuln_counts.items():
            percentage = (count / len(self.dataset)) * 100
            print(f"  {vuln}: {count} ({percentage:.1f}%)")
        
        # Financial impact by vulnerability
        if 'Financial Loss (in Million $)' in self.dataset.columns:
            financial_by_vuln = self.dataset.groupby(vuln_col)['Financial Loss (in Million $)'].agg(['sum', 'mean']).sort_values('sum', ascending=False)
            print("\nFinancial Impact by Vulnerability Type:")
            print(financial_by_vuln)
        
        # Most common attack types for each vulnerability
        print("\nAttack Types by Vulnerability:")
        for vuln in vuln_counts.head(5).index:
            vuln_data = self.dataset[self.dataset[vuln_col] == vuln]
            attack_dist = vuln_data['Attack Type'].value_counts()
            print(f"\n{vuln}:")
            for attack, count in attack_dist.head(3).items():
                print(f"  {attack}: {count}")
        
        self.analysis_results['vulnerabilities'] = {
            'vulnerability_distribution': vuln_counts.to_dict(),
            'financial_by_vulnerability': financial_by_vuln.to_dict() if 'Financial Loss (in Million $)' in self.dataset.columns else None
        }
    
    def defense_effectiveness_analysis(self):
        """Analyze effectiveness of defense mechanisms."""
        print("\n--- DEFENSE EFFECTIVENESS ANALYSIS ---")
        
        if self.dataset is None:
            print("No dataset loaded. Please load a dataset first.")
            return
        
        defense_col = 'Defense Mechanism Used'
        resolution_col = 'Incident Resolution Time (in Hours)'
        
        if defense_col not in self.dataset.columns:
            print(f"Column '{defense_col}' not found in dataset.")
            return
        
        # Defense mechanism distribution
        defense_counts = self.dataset[defense_col].value_counts()
        print("\nDefense Mechanisms Used:")
        for defense, count in defense_counts.items():
            percentage = (count / len(self.dataset)) * 100
            print(f"  {defense}: {count} ({percentage:.1f}%)")
        
        # Resolution time by defense mechanism
        if resolution_col in self.dataset.columns:
            resolution_by_defense = self.dataset.groupby(defense_col)[resolution_col].agg(['mean', 'median', 'count']).sort_values('mean')
            print("\nResolution Time by Defense Mechanism (Hours):")
            print(resolution_by_defense)
        
        # Financial impact by defense mechanism
        if 'Financial Loss (in Million $)' in self.dataset.columns:
            financial_by_defense = self.dataset.groupby(defense_col)['Financial Loss (in Million $)'].agg(['sum', 'mean']).sort_values('sum', ascending=False)
            print("\nFinancial Impact by Defense Mechanism:")
            print(financial_by_defense)
        
        self.analysis_results['defense'] = {
            'defense_distribution': defense_counts.to_dict(),
            'resolution_times': resolution_by_defense.to_dict() if resolution_col in self.dataset.columns else None,
            'financial_by_defense': financial_by_defense.to_dict() if 'Financial Loss (in Million $)' in self.dataset.columns else None
        }
    
    def data_visualization(self):
        """Create data visualizations for threat analysis."""
        print("\n--- DATA VISUALIZATION ---")
        
        if self.dataset is None:
            print("No dataset loaded. Please load a dataset first.")
            return
        
        print("Data visualization functionality - PLACEHOLDER")
        print("To implement:")
        print("1. Attack type distribution pie chart")
        print("2. Geographic threat heatmap")
        print("3. Temporal trends line chart")
        print("4. Financial impact bar charts")
        print("5. Industry vulnerability matrix")
        print("6. Interactive dashboards")
        
        # Example visualization implementations
        if not HAS_VISUALIZATION:
            print("Matplotlib and Seaborn not available. Install with: pip install matplotlib seaborn")
            return
        
        try:
            # Set up the plotting style
            try:
                plt.style.use('seaborn-v0_8')
            except OSError:
                plt.style.use('default')
            
            # Create a figure with multiple subplots
            fig, axes = plt.subplots(2, 2, figsize=(15, 12))
            fig.suptitle('Cybersecurity Threat Analysis Dashboard', fontsize=16, fontweight='bold')
            
            # 1. Attack Type Distribution
            if 'Attack Type' in self.dataset.columns:
                attack_counts = self.dataset['Attack Type'].value_counts().head(8)
                axes[0, 0].pie(attack_counts.values, labels=attack_counts.index, autopct='%1.1f%%', startangle=90)
                axes[0, 0].set_title('Attack Type Distribution')
            
            # 2. Geographic Distribution
            if 'Country' in self.dataset.columns:
                country_counts = self.dataset['Country'].value_counts().head(10)
                axes[0, 1].bar(range(len(country_counts)), country_counts.values)
                axes[0, 1].set_title('Top 10 Countries by Threat Count')
                axes[0, 1].set_xlabel('Countries')
                axes[0, 1].set_ylabel('Number of Threats')
                axes[0, 1].set_xticks(range(len(country_counts)))
                axes[0, 1].set_xticklabels(country_counts.index, rotation=45, ha='right')
            
            # 3. Temporal Trends
            if 'Year' in self.dataset.columns:
                yearly_counts = self.dataset['Year'].value_counts().sort_index()
                axes[1, 0].plot(yearly_counts.index, yearly_counts.values, marker='o', linewidth=2, markersize=6)
                axes[1, 0].set_title('Threats Over Time')
                axes[1, 0].set_xlabel('Year')
                axes[1, 0].set_ylabel('Number of Threats')
                axes[1, 0].grid(True, alpha=0.3)
            
            # 4. Financial Impact by Industry
            if 'Target Industry' in self.dataset.columns and 'Financial Loss (in Million $)' in self.dataset.columns:
                financial_by_industry = self.dataset.groupby('Target Industry')['Financial Loss (in Million $)'].sum().sort_values(ascending=False).head(8)
                axes[1, 1].barh(range(len(financial_by_industry)), financial_by_industry.values)
                axes[1, 1].set_title('Financial Impact by Industry')
                axes[1, 1].set_xlabel('Financial Loss (Million $)')
                axes[1, 1].set_yticks(range(len(financial_by_industry)))
                axes[1, 1].set_yticklabels(financial_by_industry.index)
            
            # Adjust layout and save
            plt.tight_layout()
            
            # Save the plot
            plot_filename = 'cybersecurity_threat_analysis.png'
            plt.savefig(plot_filename, dpi=300, bbox_inches='tight')
            print(f"Visualization saved as: {plot_filename}")
            
            # Show the plot
            plt.show()
            
        except Exception as e:
            print(f"Error creating visualization: {e}")
            print("This is a placeholder implementation. Full visualization features would include:")
            print("- Interactive charts with Plotly")
            print("- Geographic heatmaps")
            print("- Advanced statistical plots")
            print("- Real-time dashboard updates")
    
    def generate_threat_intelligence_report(self):
        """Generate a comprehensive threat intelligence report."""
        print("\n--- GENERATING THREAT INTELLIGENCE REPORT ---")
        
        if self.dataset is None:
            print("No dataset loaded. Please load a dataset first.")
            return
        
        print("Generating comprehensive threat intelligence report...")
        
        # Generate insights
        insights = []
        
        # Top attack type
        if 'Attack Type' in self.dataset.columns:
            top_attack = self.dataset['Attack Type'].value_counts().index[0]
            top_attack_count = self.dataset['Attack Type'].value_counts().iloc[0]
            insights.append(f"Most common attack type: {top_attack} ({top_attack_count} incidents)")
        
        # Most targeted country
        if 'Country' in self.dataset.columns:
            top_country = self.dataset['Country'].value_counts().index[0]
            top_country_count = self.dataset['Country'].value_counts().iloc[0]
            insights.append(f"Most targeted country: {top_country} ({top_country_count} incidents)")
        
        # Most vulnerable industry
        if 'Target Industry' in self.dataset.columns:
            top_industry = self.dataset['Target Industry'].value_counts().index[0]
            top_industry_count = self.dataset['Target Industry'].value_counts().iloc[0]
            insights.append(f"Most targeted industry: {top_industry} ({top_industry_count} incidents)")
        
        # Financial impact summary
        if 'Financial Loss (in Million $)' in self.dataset.columns:
            total_loss = self.dataset['Financial Loss (in Million $)'].sum()
            avg_loss = self.dataset['Financial Loss (in Million $)'].mean()
            insights.append(f"Total financial impact: ${total_loss:.2f} million (Average: ${avg_loss:.2f} million per incident)")
        
        # Vulnerability trends
        if 'Security Vulnerability Type' in self.dataset.columns:
            top_vuln = self.dataset['Security Vulnerability Type'].value_counts().index[0]
            top_vuln_count = self.dataset['Security Vulnerability Type'].value_counts().iloc[0]
            insights.append(f"Most common vulnerability: {top_vuln} ({top_vuln_count} incidents)")
        
        # Print insights
        print("\nKey Threat Intelligence Insights:")
        for i, insight in enumerate(insights, 1):
            print(f"  {i}. {insight}")
        
        # Store insights
        self.insights = insights
        
        # Generate recommendations
        recommendations = self.generate_recommendations()
        print("\nSecurity Recommendations:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        # Store report
        self.analysis_results['threat_intelligence'] = {
            'insights': insights,
            'recommendations': recommendations,
            'generated_at': datetime.now().isoformat()
        }
    
    def generate_recommendations(self):
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        if self.dataset is None:
            return recommendations
        
        # Based on most common vulnerabilities
        if 'Security Vulnerability Type' in self.dataset.columns:
            vuln_counts = self.dataset['Security Vulnerability Type'].value_counts()
            if 'Unpatched Software' in vuln_counts.index:
                recommendations.append("Implement automated patch management systems to address unpatched software vulnerabilities")
            if 'Weak Passwords' in vuln_counts.index:
                recommendations.append("Enforce strong password policies and implement multi-factor authentication")
            if 'Social Engineering' in vuln_counts.index:
                recommendations.append("Conduct regular security awareness training to combat social engineering attacks")
        
        # Based on attack types
        if 'Attack Type' in self.dataset.columns:
            attack_counts = self.dataset['Attack Type'].value_counts()
            if 'Phishing' in attack_counts.index:
                recommendations.append("Deploy advanced email security solutions and phishing simulation training")
            if 'Ransomware' in attack_counts.index:
                recommendations.append("Implement robust backup strategies and ransomware protection solutions")
            if 'DDoS' in attack_counts.index:
                recommendations.append("Deploy DDoS mitigation services and network monitoring tools")
        
        # Based on defense mechanisms
        if 'Defense Mechanism Used' in self.dataset.columns:
            defense_counts = self.dataset['Defense Mechanism Used'].value_counts()
            if 'AI-based Detection' in defense_counts.index:
                recommendations.append("Invest in AI-powered security solutions for advanced threat detection")
            if 'VPN' in defense_counts.index:
                recommendations.append("Ensure comprehensive VPN coverage and secure remote access policies")
        
        return recommendations
    
    def export_analysis_results(self):
        """Export analysis results to file."""
        print("\n--- EXPORT ANALYSIS RESULTS ---")
        
        if not self.analysis_results:
            print("No analysis results to export. Please run some analyses first.")
            return
        
        filename = input("Enter filename to save results (e.g., threat_analysis.json): ").strip()
        if not filename:
            print("Error: Filename cannot be empty.")
            return
        
        try:
            export_data = {
                'analysis_results': self.analysis_results,
                'insights': self.insights,
                'dataset_info': {
                    'shape': self.dataset.shape if self.dataset is not None else None,
                    'columns': list(self.dataset.columns) if self.dataset is not None else None
                },
                'exported_at': datetime.now().isoformat()
            }
            
            if filename.endswith('.json'):
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
            else:
                with open(filename, 'w') as f:
                    f.write(json.dumps(export_data, indent=2, default=str))
            
            print(f"Analysis results exported to {filename}")
        except Exception as e:
            print(f"Error exporting results: {e}")
    
    def run(self):
        """Main threat analysis interface."""
        while True:
            try:
                self.display_menu()
                choice = self.get_user_choice()
                
                if choice == 1:
                    self.load_dataset()
                elif choice == 2:
                    self.dataset_overview()
                elif choice == 3:
                    self.attack_type_analysis()
                elif choice == 4:
                    self.geographic_analysis()
                elif choice == 5:
                    self.industry_impact_analysis()
                elif choice == 6:
                    self.temporal_trends()
                elif choice == 7:
                    self.financial_impact_analysis()
                elif choice == 8:
                    self.vulnerability_analysis()
                elif choice == 9:
                    self.defense_effectiveness_analysis()
                elif choice == 10:
                    self.data_visualization()
                elif choice == 11:
                    self.generate_threat_intelligence_report()
                elif choice == 12:
                    self.export_analysis_results()
                elif choice == 13:
                    break
                
                if choice != 13:
                    input("\nPress Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\nReturning to main menu...")
                break
            except Exception as e:
                print(f"\nAn error occurred: {e}")
                input("Press Enter to continue...")


# Example usage and testing
if __name__ == "__main__":
    analyzer = ThreatAnalyzer()
    analyzer.run()
