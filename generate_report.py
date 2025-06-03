from fpdf import FPDF
from datetime import datetime
from visualize import generate_anomaly_plot
from mitre_mapper import map_anomaly_to_mitre
import os

def generate_pdf_report(anomalies, filename="anomaly_report.pdf", csv_path=None):
    """
    Generates a professional PDF report with anomalies and MITRE mappings
    :param anomalies: DataFrame of anomalies
    :param filename: Output PDF file name
    :param csv_path: Path to labeled flows CSV (for plot generation)
    """

    # Generate and get path to the visualization
    if not csv_path or not os.path.exists(csv_path):
        print("[-] CSV file not provided or not found. Skipping visualization.")
        plot_path = None
    else:
        plot_path = generate_anomaly_plot(
            csv_path=csv_path,
            output_image=os.path.join(os.path.dirname(filename), "anomaly_plot.png")
        )

    # Start PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Network Anomaly Report", ln=True, align='C')
    pdf.ln(5)

    # Subheader
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 10, f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True, align='R')
    pdf.ln(10)

    # Add image if available
    if plot_path and os.path.exists(plot_path):
        pdf.image(plot_path, x=10, w=190)
        pdf.ln(10)

    # Summary section
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Detected Anomalies", ln=True)
    pdf.ln(5)

    # Loop through anomalies
    for idx, row in anomalies.iterrows():
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, f"Flow #{idx}", ln=True)
        pdf.set_font("Helvetica", "", 10)

        pdf.cell(0, 8, f"Source IP      : {row.get('src', 'N/A')}")
        pdf.ln(5)
        pdf.cell(0, 8, f"Destination IP : {row.get('dst', 'N/A')}")
        pdf.ln(5)
        pdf.cell(0, 8, f"Protocol       : {row.get('proto', 'N/A')}")
        pdf.ln(5)
        pdf.cell(0, 8, f"Duration       : {row.get('duration', 'N/A'):.2f} sec")
        pdf.ln(5)
        pdf.cell(0, 8, f"Packets        : {row.get('packet_count', 'N/A')}")
        pdf.ln(5)
        pdf.cell(0, 8, f"Bytes          : {row.get('byte_count', 'N/A')}")
        pdf.ln(5)
        pdf.cell(0, 8, f"Bytes/sec      : {row.get('bytes_per_sec', 'N/A'):.2f}")
        pdf.ln(8)

        # Add mapped MITRE techniques
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 8, "MITRE ATT&CK Mappings:")
        pdf.ln(5)

        pdf.set_font("Helvetica", "", 9)
        mitre_matches = map_anomaly_to_mitre(row)
        if mitre_matches:
            for t in mitre_matches:
                pdf.cell(0, 6, f" - {t['id']} | {t['name']}")
                pdf.ln(5)
        else:
            pdf.cell(0, 6, " - No matching MITRE ATT&CK technique found")
            pdf.ln(5)

        pdf.ln(5)

    # Save file
    pdf.output(filename)
    print(f"[+] Saved PDF report to `{filename}`")