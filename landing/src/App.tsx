import Navbar from './components/Navbar'
import Hero from './components/Hero'
import HowItWorks from './components/HowItWorks'
import Stats from './components/Stats'
import QuantosSection from './components/QuantosSection'
import BuilderFlow from './components/BuilderFlow'
import L0Section from './components/L0Section'
import NetworkStatus from './components/NetworkStatus'
import TeamSection from './components/TeamSection'
import FAQ from './components/FAQ'
import CTA from './components/CTA'
import Footer from './components/Footer'

export default function App() {
  return (
    <div className="min-h-screen bg-[#05080F] relative overflow-x-hidden site-shell">
      <div className="global-ambient" aria-hidden="true" />
      <Navbar />
      <main className="relative">
        <div className="section-stage">
          <Hero />
        </div>
        <div className="section-stage section-stage-soft">
          <HowItWorks />
        </div>
        <div className="section-stage section-stage-soft">
          <Stats />
        </div>
        <div className="section-stage section-stage-wave">
          <L0Section />
        </div>
        <div className="section-stage section-stage-wave">
          <QuantosSection />
        </div>
        <div className="section-stage section-stage-soft">
          <BuilderFlow />
        </div>
        <div className="section-stage section-stage-wave">
          <NetworkStatus />
        </div>
        <div className="section-stage section-stage-soft">
          <TeamSection />
        </div>
        <div className="section-stage section-stage-soft">
          <FAQ />
        </div>
        <div className="section-stage">
          <CTA />
        </div>
      </main>
      <Footer />
    </div>
  )
}
