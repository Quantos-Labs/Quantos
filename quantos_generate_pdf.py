import os
from fpdf import FPDF

class QuantosPDF(FPDF):
    def header(self):
        # Draw a subtle top banner
        self.set_fill_color(18, 30, 49) # Deep blue/grey (Quantos Brand Color)
        self.rect(0, 0, 210, 15, "F")
        
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, -2, "QUANTOS NETWORK - INFRASTRUCTURE PLAN & CAPACITY REPORT", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_y(20)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Quantos Labs Confidential - Page {self.page_no()}/{{nb}}", align="C")

def create_quantos_report(output_path):
    pdf = QuantosPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.alias_nb_pages()

    # Document Title
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(18, 30, 49)
    pdf.cell(0, 10, "Specifications Testnet Quantos", new_x="LMARGIN", new_y="NEXT", align="L")
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 8, "Plan de Deploiement OVH ECO & Analyse de Capacite TPS", new_x="LMARGIN", new_y="NEXT", align="L")
    
    pdf.set_draw_color(18, 30, 49)
    pdf.set_line_width(0.5)
    pdf.line(10, 40, 200, 40)
    pdf.ln(10)

    # 1. Résumé Exécutif
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(18, 30, 49)
    pdf.cell(0, 8, "1. Resume Executif", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(40, 40, 40)
    pdf.multi_cell(0, 5, (
        "Ce rapport technique definit l'architecture d'infrastructure recommandee pour le lancement du "
        "Testnet public de Quantos (L1/L0) en utilisant la gamme de serveurs ECO (Rise) d'OVHcloud. "
        "En s'appuyant sur l'analyse en profondeur du code source de Quantos, notamment les composants "
        "de consensus DAG, le routage cross-shard atomique (CSAP) et la generation de preuves zk-STARK (Winterfell), "
        "nous presentons une configuration optimale garantissant un debit maximal pour un cout maitrise."
    ))
    pdf.ln(4)

    # 2. Besoins Matériels Identifiés (Analyse du Code)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(18, 30, 49)
    pdf.cell(0, 8, "2. Analyse des Goulots d'Etranglement & Besoins Code", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 5, (
        "- Calcul zk-STARK (CPU/RAM-Intensif) : La generation de preuves Winterfell (stark_accelerated.rs) exige "
        "des calculs LDE (Low-Degree Extension) et FRI multi-threades. Une frequence d'horloge monocoeur elevee "
        "(> 4.5 GHz) et 64 a 128 Go de RAM sont indispensables pour eviter les debordements de memoire (OOM).\n"
        "- Database & Consensus DAG (I/O-Intensif) : L'ecriture et la lecture continues des blocs DAG et des recus de "
        "transactions (quantos.rs/storage.rs) necessitent l'utilisation de disques SSD NVMe montes en RAID-1.\n"
        "- Reseau Sharde (Bande Passante) : Le protocole CSAP de verrouillage a deux phases requiert des echanges "
        "ultra-rapides entre validateurs. Le reseau prive OVH vRack (10 Gbps) est recommande pour isoler ce trafic."
    ))
    pdf.ln(4)

    # 3. Architecture d'Infrastructure Recommandée
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(18, 30, 49)
    pdf.cell(0, 8, "3. Plan d'Infrastructure Recommande (5 Serveurs)", new_x="LMARGIN", new_y="NEXT")

    # Table Header
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(240, 243, 246)
    pdf.set_text_color(18, 30, 49)
    pdf.cell(25, 7, "Noeud", border=1, fill=True)
    pdf.cell(25, 7, "Gamme OVH", border=1, fill=True)
    pdf.cell(45, 7, "CPU", border=1, fill=True)
    pdf.cell(25, 7, "RAM", border=1, fill=True)
    pdf.cell(45, 7, "Disques NVMe", border=1, fill=True)
    pdf.cell(25, 7, "Cout HT/mois", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    # Table Body
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(40, 40, 40)
    
    nodes_data = [
        ("Noeud 1 (Prover)", "Rise-3 (AMD)", "Ryzen 7 5800X (8c/16t)", "128 Go DDR4", "2x 1.92 To NVMe", "90 EUR"),
        ("Noeud 2 (Validator)", "Rise-1 (Intel)", "Xeon-E 2386G (6c/12t)", "64 Go DDR4", "2x 512 Go NVMe", "65 EUR"),
        ("Noeud 3 (Validator)", "Rise-1 (Intel)", "Xeon-E 2386G (6c/12t)", "64 Go DDR4", "2x 512 Go NVMe", "65 EUR"),
        ("Noeud 4 (Validator)", "Rise-1 (Intel)", "Xeon-E 2386G (6c/12t)", "64 Go DDR4", "2x 512 Go NVMe", "65 EUR"),
        ("Noeud 5 (RPC/Gate)", "Rise-1 (Intel)", "Xeon-E 2386G (6c/12t)", "64 Go DDR4", "2x 512 Go NVMe", "65 EUR"),
    ]
    
    for row in nodes_data:
        pdf.cell(25, 6, row[0], border=1)
        pdf.cell(25, 6, row[1], border=1)
        pdf.cell(45, 6, row[2], border=1)
        pdf.cell(25, 6, row[3], border=1)
        pdf.cell(45, 6, row[4], border=1)
        pdf.cell(25, 6, row[5], border=1, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(18, 30, 49)
    pdf.ln(2)
    pdf.cell(0, 6, "Total Budget Mensuel : 350 EUR HT (environ 420 EUR TTC) | Annuel : 4 200 EUR HT", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # 4. Estimation du Débit (TPS) & Performance
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(18, 30, 49)
    pdf.cell(0, 8, "4. Analyse du Debit Transactionnel (TPS)", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(40, 40, 40)
    pdf.multi_cell(0, 5, (
        "L'usage des zk-STARKs via Winterfell et l'architecture sharding de Quantos permettent d'optimiser "
        "drastiquement le debit. Voici les performances theoriques atteignables sur ce cluster :"
    ))
    pdf.ln(2)

    # Performance Box
    pdf.set_fill_color(245, 247, 250)
    pdf.set_draw_color(200, 210, 220)
    pdf.rect(10, pdf.get_y(), 190, 45, "FD")
    
    pdf.set_y(pdf.get_y() + 3)
    pdf.set_x(15)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(18, 30, 49)
    pdf.cell(0, 5, "Niveaux de Performance Estimes :", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(40, 40, 40)
    pdf.ln(1)
    bullet_points = [
        "Transactions Standards L1 (Simples transfers) : ~35 000 a 50 000 TPS par shard.",
        "Transactions Cross-Shard Batchees (STARK) : 100 000+ TPS cumules grace au regroupement de 1 000 tx par preuve.",
        "Calcul de Preuve STARK (Noeud 1 Prover) : ~300ms a 600ms pour generer la preuve d'un batch de 1 000 tx.",
        "Temps de Finalite Post-Quantique (L0 finality) : < 1.5 seconde par checkpoint sur reseau prive vRack.",
    ]
    for bp in bullet_points:
        pdf.set_x(15)
        pdf.cell(0, 4.5, f"- {bp}", new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(12)

    # 5. Recommandations Stratégiques
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(18, 30, 49)
    pdf.cell(0, 8, "5. Plan d'Action & Prochaines Etapes", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(40, 40, 40)
    pdf.multi_cell(0, 5, (
        "1. Phase Pilote (Devnet) : Commander deux serveurs Rise-1 pour demarrer la topologie et valider la latence.\n"
        "2. Interconnexion Privee (vRack) : Configurer le reseau prive virtuel gratuit d'OVH pour relier les noeuds "
        "sans exposer les ports de consensus (ports p2p et CSAP) sur Internet.\n"
        "3. Deploiement du Prover (AMD Ryzen) : Isoler le worker de preuve zk-STARK (stark_accelerated.rs) "
        "uniquement sur le serveur premium Rise-3 pour ne pas perturber les validateurs sensibles a la latence."
    ))

    # Save PDF
    pdf.output(output_path)
    print(f"PDF successfully generated at {output_path}")

if __name__ == "__main__":
    create_quantos_report("/Users/wayle/Quantos_labs/quantos/quantos_testnet_specifications.pdf")
